package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand/v2"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/shirou/gopsutil/disk"

	// "github.com/google/gopacket/pcapgo"
	"github.com/gorilla/websocket"
)

type Usuario struct {
	ID      int    `json:"id"`
	Usuario string `json:"usuario"`
	Senha   string `json:"senha"`
	EhAdm   bool   `json:"eh_adm"`
	Ativo   bool   `json:"ativo"`
}

// Estrutura para o JSON recebido
type FolderPath struct {
	Name string `json:"name"`
}

// Configura o WebSocket upgrader

type ConnUser struct {
	Username   string `json:"username"`
	CurrFolder string `json:"filepath"`
}

type FileType struct {
	FileName string `json:"filename"`
	Type     string `json:"type"` // file folder

}

type UserFolder struct {
	FreeDisk float32    `json:"free_disk"`
	Path     string     `json:"path"`
	Files    []FileType `json:"files"`
}

type WebSocketRes struct {
	Ws   *websocket.Conn
	Text []byte
}

type DownloadRequest struct {
	Filename string `json:"filename"`
	Path     string `json:"path"`
}

type FolderRequest struct {
	Name string `json:"name"`
	Path string `json:"path"`
}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

var arquivoUsuarios = "usuarios.json"

var clients = make(map[*websocket.Conn]bool)

var users = make(map[*websocket.Conn]ConnUser)

var broadcast = make(chan WebSocketRes)

var allFiles = make([]FileType, 0, 10)

const (
	snaplen     = 1600                                             // Tamanho máximo do pacote
	promiscuous = false                                            // Captura em modo promíscuo
	filter      = "tcp port 445 and tcp[tcpflags] & tcp-push != 0" // Filtro para pacotes da porta 445 com dados
	defaultPath = "../../../compartilhado/"
)

type UserRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func findActiveNetworkInterface() (string, error) {
	// Obtém a lista de interfaces de rede
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", fmt.Errorf("erro ao obter interfaces de rede: %v", err)
	}

	// Itera pelas interfaces
	for _, iface := range interfaces {
		// Ignora interfaces inativas ou sem suporte a multicast
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagMulticast == 0 {
			continue
		}

		// Obtém os endereços associados à interface
		addresses, err := iface.Addrs()
		if err != nil {
			continue // Ignora interfaces que não podem ter seus endereços listados
		}

		// Verifica se algum dos endereços está associado a um IP válido
		for _, addr := range addresses {
			// Parseia o endereço para determinar se é IPv4 ou IPv6
			ip, _, err := net.ParseCIDR(addr.String())
			if err != nil {
				continue
			}

			// Verifica se o IP não é de loopback
			if !ip.IsLoopback() && ip.To4() != nil {
				return iface.Name, nil // Retorna a interface ativa com um IPv4 válido
			}
		}
	}

	return "", fmt.Errorf("nenhuma interface de rede ativa conectada à internet foi encontrada")
}

// func userHandler(w http.ResponseWriter, r *http.Request) {
// 	if r.Method == http.MethodPost {
// 		createUserHandler(w, r)
// 	} else if r.Method == http.MethodDelete {
// 		deleteUserHandler(w, r)
// 	} else {
// 		http.Error(w, "Apenas POST e DELETE são suportados.", http.StatusMethodNotAllowed)
// 		return
// 	}
// }

func createUser(username string, password string) error {

	// Verifica se os campos estão preenchidos
	if username == "" || password == "" {
		return fmt.Errorf("username e password são obrigatórios")
	}

	// Cria o usuário no sistema Linux
	cmdAddUser := exec.Command("sudo", "useradd", username)
	err := cmdAddUser.Run()
	if err != nil {
		return fmt.Errorf("erro ao criar o usuário Linux: %w", err)
	}

	// Define a senha do usuário
	cmdSetPassword := exec.Command("sudo", "sh", "-c", fmt.Sprintf("echo '%s:%s' | chpasswd", username, password))
	err = cmdSetPassword.Run()
	if err != nil {
		return fmt.Errorf("erro ao definir a senha do usuário: %w", err)
	}

	// Adiciona o usuário ao Samba
	cmdSmb := exec.Command("sudo", "smbpasswd", "-a", username)
	cmdSmb.Stdin = nil
	cmdSmb.Stdout = nil
	cmdSmb.Stderr = nil
	cmdSmbInput, _ := cmdSmb.StdinPipe()
	err = cmdSmb.Start()
	if err != nil {
		return fmt.Errorf("erro ao inicializar o comando smbpasswd: %w", err)
	}

	_, err = cmdSmbInput.Write([]byte(fmt.Sprintf("%s\n%s\n", password, password)))
	cmdSmbInput.Close()
	if err != nil {
		return fmt.Errorf("erro ao passar a senha para o smbpasswd: %w", err)
	}

	err = cmdSmb.Wait()
	if err != nil {
		return fmt.Errorf("erro ao criar o usuário no Samba: %w", err)
	}

	// Caminho do diretório compartilhado
	directoryPath := fmt.Sprintf("/compartilhado/priv_%s", username)

	// Criar o diretório
	err = os.MkdirAll(directoryPath, 0700)
	if err != nil {
		return fmt.Errorf("erro ao criar o diretório: %w", err)
	}
	fmt.Printf("Diretório %s criado com sucesso.\n", directoryPath)

	// Alterar o dono do diretório para o usuário criado
	cmdChown := exec.Command("sudo", "chown", fmt.Sprintf("%s:%s", username, username), directoryPath)
	err = cmdChown.Run()
	if err != nil {
		return fmt.Errorf("erro ao alterar as permissões do diretório: %w", err)
	}
	fmt.Printf("Permissões de dono alteradas para o usuário %s.\n", username)

	// Garantir que as permissões do diretório sejam 700
	if err := os.Chmod(directoryPath, 0700); err != nil {
		return fmt.Errorf("erro ao alterar as permissões do diretório: %w", err)
	}
	fmt.Printf("Permissões definidas como 700 para o diretório %s.\n", directoryPath)

	// Nao retorna erro
	return nil
}
func deleteUser(username string) error {
	// Executar os comandos para remover o usuário
	if err := removeUser(username); err != nil {
		return fmt.Errorf("Erro ao remover usuário")
	}

	return nil
}

func removeUser(username string) error {
	// Remover o usuário do Samba
	cmdRemoveSmb := exec.Command("sudo", "smbpasswd", "-x", username)
	if err := cmdRemoveSmb.Run(); err != nil {
		return fmt.Errorf("erro ao remover o usuário do Samba: %w", err)
	}
	fmt.Printf("Usuário %s removido do Samba.\n", username)

	// Remover o usuário do sistema
	cmdRemoveUser := exec.Command("sudo", "userdel", username)
	if err := cmdRemoveUser.Run(); err != nil {
		return fmt.Errorf("erro ao remover o usuário do sistema: %w", err)
	}
	fmt.Printf("Usuário %s removido do sistema.\n", username)

	// Remover o diretório compartilhado
	directoryPath := fmt.Sprintf("/compartilhado/priv_%s", username)
	cmdRemoveDir := exec.Command("sudo", "rm", "-r", directoryPath)
	if err := cmdRemoveDir.Run(); err != nil {
		return fmt.Errorf("erro ao remover o diretório compartilhado: %w", err)
	}
	fmt.Printf("Diretório %s removido com sucesso.\n", directoryPath)

	return nil
}

func wsConnection(w http.ResponseWriter, r *http.Request) {
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("Erro ao estabelecer WebSocket:", err)
		return
	}
	defer ws.Close()

	clientAddr := ws.RemoteAddr().String()
	log.Printf("Novo usuário conectado: %s\n", clientAddr)
	number := rand.IntN(2)
	if number%2 == 0 {
		users[ws] = ConnUser{
			Username:   clientAddr,
			CurrFolder: defaultPath,
		}
	} else {
		users[ws] = ConnUser{
			Username:   clientAddr,
			CurrFolder: defaultPath,
		}
	}
	clients[ws] = true
	sendDataToUser()

	for {
		// var fileMessage FileMessage
		// Lê a mensagem de texto com os metadados do arquivo
		_, msg, err := ws.ReadMessage()
		if err != nil {
			log.Println("Erro ao ler mensagem de metadados:", err)
			delete(clients, ws)
			return
		}
		fmt.Printf("mensagem recebida pelo ws: %s\n", string(msg))
		var folderPath FolderPath
		if err := json.Unmarshal(msg, &folderPath); err != nil {
			log.Println("Mensagem inválida recebida:", err)
			continue
		}
		users[ws] = ConnUser{
			Username:   users[ws].Username,
			CurrFolder: string(folderPath.Name) + "/",
		}
		fmt.Printf("O novo diretorio sera: %s\n", users[ws].CurrFolder)
		sendDataToUser()
	}
}

func sendDataToUser() {
	// load file names into RAM
	for ws, user := range users {
		// fmt.Printf("Usuario: %s e Path: %s\n", user.Username, user.CurrFolder)

		usage, err := disk.Usage("/")
		if err != nil {
			log.Fatalf("Erro ao obter informações do disco: %v", err)
		}

		// Porcentagem de disco disponível
		availablePercentage := (float64(usage.Free) / float64(usage.Total)) * 100
		userFolder := UserFolder{
			FreeDisk: float32(availablePercentage),
			Path:     user.CurrFolder,
		}
		files, err := os.ReadDir(user.CurrFolder)
		if err != nil {
			log.Fatal(err)
		}
		for _, f := range files {
			if !f.IsDir() {
				allFiles = append(allFiles,
					FileType{
						FileName: f.Name(),
						Type:     "file",
					})
			} else {
				allFiles = append(allFiles,
					FileType{
						FileName: f.Name(),
						Type:     "folder",
					})
			}

		}
		userFolder.Files = allFiles
		responseJSON, err := json.Marshal(userFolder)
		if err != nil {
			log.Println("Erro ao serializar resposta:", err)
			return
		}

		message := WebSocketRes{
			Ws:   ws,
			Text: responseJSON,
		}
		// fmt.Printf("current path: %s\n", responseJSON)
		// Envia a mensagem para o canal de broadcast
		broadcast <- message
		allFiles = []FileType{}
	}
}

func handleMessages() {
	for {
		// Lê a mensagem do canal de broadcast
		msg := <-broadcast
		// Envia a mensagem para cada cliente conectado

		err := msg.Ws.WriteMessage(websocket.TextMessage, msg.Text)
		if err != nil {
			fmt.Println("Erro ao enviar mensagem:", err)
			msg.Ws.Close()
			delete(clients, msg.Ws)
		}

	}
}

func createFolder(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Metodo nao permitido", http.StatusMethodNotAllowed)
	}

	var folder FolderRequest
	err := json.NewDecoder(r.Body).Decode(&folder)
	if err != nil {
		http.Error(w, "Erro ao decodificar corpo da req", http.StatusBadRequest)
	}

	err = os.Mkdir(filepath.Join(folder.Path, folder.Name), os.ModePerm)
	if err != nil {
		log.Println("Erro ao criar diretorio")
		http.Error(w, "Erro ao criar diretorio", http.StatusBadRequest)
	}

	sendDataToUser()

}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		// Responde com status 200 para requisições OPTIONS e termina aqui
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func lerUsuarios(nomeArquivo string) ([]Usuario, error) {
	var usuarioFile struct {
		Usuarios []Usuario `json:"usuarios"`
	}
	arquivo, err := os.Open(nomeArquivo)
	if err != nil {
		return nil, err
	}
	defer arquivo.Close()

	dec := json.NewDecoder(arquivo)
	if err := dec.Decode(&usuarioFile); err != nil {
		return nil, err
	}
	return usuarioFile.Usuarios, nil
}

func salvarUsuarios(nomeArquivo string, usuarios []Usuario) error {
	var usuarioFile struct {
		Usuarios []Usuario `json:"usuarios"`
	}
	usuarioFile.Usuarios = usuarios
	arquivo, err := os.Create(nomeArquivo)
	if err != nil {
		return err
	}
	defer arquivo.Close()

	enc := json.NewEncoder(arquivo)
	return enc.Encode(usuarioFile)
}

func registrarUsuario(usuario, senha string) error {
	usuarios, err := lerUsuarios(arquivoUsuarios)
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	for _, u := range usuarios {
		if u.Usuario == usuario {
			return fmt.Errorf("o usuário '%s' já existe", usuario)
		}
	}

	// Definir ID e tipo de usuário
	var novoUsuario Usuario
	novoUsuario.ID = len(usuarios) + 1
	novoUsuario.Usuario = usuario
	novoUsuario.Senha = senha
	novoUsuario.Ativo = true
	novoUsuario.EhAdm = true

	usuarios = append(usuarios, novoUsuario)
	err = salvarUsuarios(arquivoUsuarios, usuarios)
	if err != nil {
		return err
	}
	return createUser(usuario, senha)
}

func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, senha, ok := r.BasicAuth()
		if !ok {
			http.Error(w, "Autenticação necessária", http.StatusUnauthorized)
			return
		}

		validado, err := verificarLogin(username, senha)
		if err != nil || !validado {
			http.Error(w, "Credenciais inválidas", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func authADMMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, senha, ok := r.BasicAuth()
		if !ok {
			http.Error(w, "Autenticação necessária", http.StatusUnauthorized)
			return
		}

		usuarios, err := lerUsuarios(arquivoUsuarios)
		if err != nil {
			http.Error(w, "Credenciais inválidas", http.StatusUnauthorized)
		}

		for _, user := range usuarios {
			if user.Usuario == username && user.Senha == senha && user.EhAdm {
				next.ServeHTTP(w, r)
				return
			}
		}
		http.Error(w, "Credenciais inválidas", http.StatusUnauthorized)
	})
}

func ativarUsuario(id int) error {
	usuarios, err := lerUsuarios(arquivoUsuarios)
	if err != nil {
		return err
	}

	for i, user := range usuarios {
		if user.ID == id {
			usuarios[i].Ativo = true
			return salvarUsuarios(arquivoUsuarios, usuarios)
		}
	}
	return errors.New("usuário não encontrado")
}

func deletarUsuario(id int) error {
	usuarios, err := lerUsuarios(arquivoUsuarios)
	if err != nil {
		return err
	}

	for i, user := range usuarios {
		if user.ID == id {
			usuarios = append(usuarios[:i], usuarios[i+1:]...)
			err = salvarUsuarios(arquivoUsuarios, usuarios)
			return deleteUser(user.Usuario)
		}
	}
	return errors.New("usuário não encontrado")
}

func verificarLogin(usuario, senha string) (bool, error) {
	usuarios, err := lerUsuarios(arquivoUsuarios)
	if err != nil {
		return false, err
	}

	for _, user := range usuarios {
		if user.Usuario == usuario && user.Senha == senha && user.Ativo {
			return true, nil
		}
	}
	return false, errors.New("usuário ou senha inválidos ou conta inativa")
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("LoginHandler")
	if r.Method != http.MethodPost {
		http.Error(w, "Método não permitido", http.StatusMethodNotAllowed)
		return
	}

	var credenciais struct {
		Usuario string `json:"usuario"`
		Senha   string `json:"senha"`
	}
	err := json.NewDecoder(r.Body).Decode(&credenciais)
	fmt.Println(credenciais.Usuario)
	if err != nil {
		http.Error(w, "Dados inválidos", http.StatusBadRequest)
		return
	}

	validado, err := verificarLogin(credenciais.Usuario, credenciais.Senha)
	if err != nil {
		http.Error(w, "DEU RUIM"+err.Error(), http.StatusUnauthorized)
		return
	} else if !validado {
		http.Error(w, "Usuário ou senha incorretos", http.StatusUnauthorized)
	}

	fmt.Fprintln(w, "Login bem-sucedido!")
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Método não permitido", http.StatusMethodNotAllowed)
		return
	}

	var credenciais struct {
		Usuario string `json:"usuario"`
		Senha   string `json:"senha"`
	}
	err := json.NewDecoder(r.Body).Decode(&credenciais)
	if err != nil {
		http.Error(w, "Dados inválidos", http.StatusBadRequest)
		return
	}

	err = registrarUsuario(credenciais.Usuario, credenciais.Senha)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	fmt.Fprintln(w, "Usuário registrado com sucesso!")
}

func activateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Método não permitido", http.StatusMethodNotAllowed)
		return
	}

	var request struct {
		ID int `json:"id"`
	}
	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		http.Error(w, "Dados inválidos", http.StatusBadRequest)
		return
	}

	err = ativarUsuario(request.ID)
	if err != nil {
		http.Error(w, "Erro ao ativar usuário", http.StatusInternalServerError)
		return
	}

	fmt.Fprintln(w, "Usuário ativado com sucesso!")
}

func getUsuarios(w http.ResponseWriter, r *http.Request) {
	// Lê os usuários do arquivo
	usuarios, err := lerUsuarios(arquivoUsuarios)
	if err != nil {
		http.Error(w, "Erro ao ler usuários", http.StatusInternalServerError)
		return
	}

	// Define o cabeçalho como JSON
	w.Header().Set("Content-Type", "application/json")

	// Serializa a lista de usuários para JSON e envia para o cliente
	err = json.NewEncoder(w).Encode(usuarios)
	if err != nil {
		http.Error(w, "Erro ao codificar usuários", http.StatusInternalServerError)
		return
	}
}

func deleteHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Método não permitido", http.StatusMethodNotAllowed)
		return
	}

	var request struct {
		ID int `json:"id"`
	}
	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		http.Error(w, "Dados inválidos", http.StatusBadRequest)
		return
	}

	err = deletarUsuario(request.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	fmt.Fprintln(w, "Usuário deletado com sucesso!")
}

func fileReceiver(w http.ResponseWriter, r *http.Request) {

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Verifica se o método é POST
	if r.Method != http.MethodPost {
		http.Error(w, "Método não permitido", http.StatusMethodNotAllowed)
		return
	}
	r.ParseMultipartForm(10 << 20) // 10MB

	// Obtém o arquivo do formulário usando o nome do campo "file"
	file, handler, err := r.FormFile("file")
	if err != nil {
		fmt.Println("Erro ao obter o arquivo:", err)
		http.Error(w, "Erro ao obter o arquivo", http.StatusBadRequest)
		return
	}
	defer file.Close()

	path := r.FormValue("path")
	if path == "" {
		fmt.Println("Caminho não fornecido")
		http.Error(w, "Caminho do arquivo é obrigatório", http.StatusBadRequest)
		return
	}
	fmt.Println(path)

	// Cria um novo arquivo no sistema para salvar o upload
	dst, err := os.Create(path + handler.Filename)
	if err != nil {
		fmt.Println("Erro ao criar o arquivo:", err)
		http.Error(w, "Erro ao salvar o arquivo", http.StatusInternalServerError)
		return
	}
	defer dst.Close()

	// Copia o conteúdo do arquivo recebido para o novo arquivo
	_, err = io.Copy(dst, file)
	if err != nil {
		fmt.Println("Erro ao salvar o conteúdo do arquivo:", err)
		http.Error(w, "Erro ao salvar o arquivo", http.StatusInternalServerError)
		return
	}

	fmt.Println("Arquivo recebido:", handler.Filename, "Tamanho:", handler.Size, "bytes")
	fmt.Fprintf(w, "Arquivo %s recebido com sucesso!", handler.Filename)
	for _, file := range allFiles {
		if handler.Filename != file.FileName {
			allFiles = append(allFiles, FileType{
				FileName: handler.Filename,
				Type:     "file",
			})
		}
	}
	sendDataToUser()
}

func downloadFile(w http.ResponseWriter, r *http.Request) {

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Verifica se o método é POST
	if r.Method != http.MethodPost {
		http.Error(w, "Método não permitido", http.StatusMethodNotAllowed)
		return
	}

	// Decodifica o corpo JSON
	var donwloadRequest DownloadRequest
	err := json.NewDecoder(r.Body).Decode(&donwloadRequest)
	if err != nil {
		http.Error(w, "Erro ao decodificar o corpo da requisição", http.StatusBadRequest)
		return
	}

	// Exibe as informações recebidas

	filename := donwloadRequest.Filename
	path := donwloadRequest.Path

	w.Header().Set("Content-Disposition", "attachment; filename="+strconv.Quote(filename))
	w.Header().Set("Content-Type", "application/octet-stream")

	http.ServeFile(w, r, path+filename)

}

// New function to trigger resending data to all connected users
func resendData(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Método não permitido", http.StatusMethodNotAllowed)
		return
	}

	// Trigger sending data to all users
	sendDataToUser()

	// Respond to the client that the operation was successful
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Data resend initiated for all users.")
}

func deleteFolder(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Método não permitido", http.StatusMethodNotAllowed)
		return
	}

	var folder FolderRequest
	err := json.NewDecoder(r.Body).Decode(&folder)
	if err != nil {
		http.Error(w, "Erro ao decodificar corpo da req", http.StatusBadRequest)
	}

	err = os.Remove(filepath.Join(folder.Path, folder.Name))
	if err != nil {
		log.Println("Erro ao remover diretorio")
		http.Error(w, "Erro ao criar diretorio", http.StatusBadRequest)
	}

	sendDataToUser()

}

type RenameRequest struct {
	OldPath string `json:"oldpath"`
	NewPath string `json:"newpath"` // file folder

}

func renameHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Verifica se o método é POST
	if r.Method != http.MethodPost {
		http.Error(w, "Método não permitido", http.StatusMethodNotAllowed)
		return
	}
	var renameRequest RenameRequest
	err := json.NewDecoder(r.Body).Decode(&renameRequest)
	if err != nil {
		http.Error(w, "Erro ao decodificar corpo da req", http.StatusBadRequest)
	}
	// Renomeia o arquivo ou pasta
	err = os.Rename(renameRequest.OldPath, renameRequest.NewPath)
	if err != nil {
		fmt.Println("Erro ao renomear o arquivo ou pasta:", err)
		http.Error(w, "Erro ao renomear o arquivo ou pasta", http.StatusInternalServerError)
		return
	}

	fmt.Printf("Renomeado de '%s' para '%s'\n", renameRequest.OldPath, renameRequest.NewPath)
	fmt.Fprintf(w, "Arquivo ou pasta renomeado com sucesso!")
	sendDataToUser()
}

func monitorPort445() {

	device, _ := findActiveNetworkInterface()

	// Porta SMB padrão
	port := "445"
	// Abrir dispositivo para captura
	handle, err := pcap.OpenLive(device, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatalf("Erro ao abrir dispositivo: %v", err)
	}
	defer handle.Close()

	// Criar filtro para SMB na porta 445
	filter := fmt.Sprintf("tcp port %s", port)
	if err := handle.SetBPFFilter(filter); err != nil {
		log.Fatalf("Erro ao definir filtro: %v", err)
	}
	fmt.Printf("Monitorando conexões SMB na porta %s na interface %s...\n", port, device)

	// Captura de pacotes
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		// Extrair a camada IP
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer == nil {
			return // Ignorar pacotes não IPv4
		}

		// Extrair informações úteis do pacote
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer == nil {
			return
		}

		tcp, _ := tcpLayer.(*layers.TCP)
		payload := tcp.Payload
		// Verificar se o payload contém dados SMB
		if len(payload) > 0 {
			sendDataToUser()
		}
	}
}

func main() {
	mux := http.NewServeMux()

	mux.Handle("/ws", http.HandlerFunc(wsConnection))
	// mux.HandleFunc("/user", userHandler)
	mux.Handle("/fileReceiver", authMiddleware(http.HandlerFunc(fileReceiver)))
	mux.Handle("/createFolder", authMiddleware(http.HandlerFunc(createFolder)))
	mux.Handle("/deleteFolder", authMiddleware(http.HandlerFunc(deleteFolder)))
	mux.HandleFunc("/downloadFile", downloadFile)
	mux.HandleFunc("/resendData", resendData)
	mux.Handle("/login", (http.HandlerFunc(loginHandler)))
	mux.Handle("/register", (http.HandlerFunc(registerHandler)))
	mux.Handle("/activate", authADMMiddleware(http.HandlerFunc(activateHandler)))
	mux.Handle("/renameFolder", authADMMiddleware(http.HandlerFunc(renameHandler)))
	mux.Handle("/listarUsuarios", authADMMiddleware(http.HandlerFunc(getUsuarios)))

	// go monitorPort445()
	go handleMessages()

	newpath := filepath.Join(defaultPath, "OtherDocs")
	err := os.MkdirAll(newpath, os.ModePerm)
	if err != nil {
		return
	}

	fmt.Println("Servidor iniciado em :8080")
	log.Fatal(http.ListenAndServe(":8080", corsMiddleware(mux)))
}
