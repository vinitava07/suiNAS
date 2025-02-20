# SuíNAS

SuíNAS é um projeto para criar um NAS inuitivo em um Raspberry PI, tornando o compartilhamento e backup de dados mais seguro e eficiente.
O projeto conta com uma interface Web para a navegação pelo sistema de arquivos, um sistema de registro e login de usuários, pastas particulares e gerênciamento de arquivos.
Se conectando na rede local e acessando o IP do raspberry você já consegue utilizar o aplicativo através de qualquer dispositivo e para usuários mais experientes existe um serviço SAMBA
rodando para uso através dos diretórios do próprio computador.

## Alunos integrantes da equipe

* Arthur Castro
* Caio Ronan
* Leonardo Buldrini
* Vinícius Tavares
* Wanderson de Souza 

## Professores responsáveis

* Felipe Domingos da Cunha
* Matheus Alcântara Souza
* Rafael Henriques Nogueira Diniz

## Instruções de utilização

### No servidor
Para rodar o aplicativo web basta ir na pasta do frontent e executar o Node na versão dev com `npm run dev`
Para rodar o backend vá no diretório do backend e execute `sudo go run .`
E execute o SAMBA no Linux.

### Para o usuário
No desktop do usuário rode o código em python para abrir a interface que encontra o raspberry e conecte no IP encontrado.
