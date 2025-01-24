import "./Home.css";
import file_upload from "../assets/file_upload.png";
import suinasLogo from "../assets/suinas_logo.png";
import { useState, useEffect, useRef } from "react";
import { BsArrowLeft } from "react-icons/bs";
import { AiOutlinePlus } from "react-icons/ai"; // Ícone de "+"
import { checkLoginStatus, logout } from '../auth/authService';


function Home() {
  const [file, setFile] = useState(null);
  const [directory, setData] = useState({ free_disk: 100, path: "", files: [] });
  const [contextMenu, setContextMenu] = useState({ visible: false, x: 0, y: 0, item: null });
  const contextMenuRef = useRef(null);
  const socket = useRef(null);
  const ip = "192.168.100.160";

  useEffect(() => {
    socket.current = new WebSocket(`ws://${ip}:8080/ws`);

    socket.current.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        if (data.path && Array.isArray(data.files)) {
          setData(data);
          console.log(data.free_disk);

        } else {
          console.error("Formato inesperado de dados recebidos:", data);
        }
      } catch (error) {
        console.error("Erro ao parsear os dados recebidos:", error);
      }
    };

    return () => {
      if (socket.current) {
        socket.current.close();
      }
    };
  }, []);

  const handleLeftClick = (item) => {
    if (item.type === "folder") {
      if (socket.current && socket.current.readyState === WebSocket.OPEN) {
        socket.current.send(
          JSON.stringify({ name: `${directory.path + item.filename}` })
        );
      } else {
        console.error("WebSocket não está conectado.");
      }
    } else {
      handleDownload(item.filename, directory.path);
    }
  };

  const handleItemClick = (item, event) => {
    event.preventDefault(); // Prevent default behavior
    const { clientX, clientY } = event;
    setContextMenu({ visible: true, x: clientX, y: clientY, item });
  };

  const handleOutsideClick = (event) => {
    if (contextMenuRef.current && !contextMenuRef.current.contains(event.target)) {
      setContextMenu({ ...contextMenu, visible: false });
    }
  };

  useEffect(() => {
    if (contextMenu.visible) {
      document.addEventListener("mousedown", handleOutsideClick);
    } else {
      document.removeEventListener("mousedown", handleOutsideClick);
    }

    return () => {
      document.removeEventListener("mousedown", handleOutsideClick);
    };
  }, [contextMenu.visible]);

  const handleReturnClick = () => {
    if (socket.current && socket.current.readyState === WebSocket.OPEN) {
      if (directory.path.localeCompare("../../../compartilhado/") == 0) {
        alert("Voce está no diretório raiz");
      } else {
        let result = directory.path.replace(/\/[^/]+\/$/, "");
        socket.current.send(JSON.stringify({ name: `${result}` }));
      }
    } else {
      console.error("WebSocket não está conectado.");
    }
  };

  const handleLogout = () => {
    logout();
    setLogged(false);
  };

  const handleCreateFolder = async () => {
    const username = localStorage.getItem("username");
    const password = localStorage.getItem("password");
    const encodedCredentials = btoa(`${username}:${password}`);
    var resp = window.prompt("Digite o nome da pasta")
    try {
      const response = await fetch(`http://${ip}:8080/createFolder`, {
        method: "POST",

        headers: {
          "Content-Type": "application/json", // Definindo o tipo de conteúdo como JSON
          Authorization: `Basic ${encodedCredentials}`, // Cabeçalho de autenticação
        },
        body: JSON.stringify({ name: resp, path: directory.path }),
      });
    } catch (error) {
      console.error("erro ao criar pasta: ", error);
    }
  };




  const handleDelete = async () => {
    const username = localStorage.getItem("username");
    const password = localStorage.getItem("password");
    const encodedCredentials = btoa(`${username}:${password}`);
    try {
      const response = await fetch(`http://${ip}:8080/deleteFolder`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json", // Definindo o tipo de conteúdo como JSON
          Authorization: `Basic ${encodedCredentials}`, // Cabeçalho de autenticação
        },
        body: JSON.stringify({ name: contextMenu.item.filename, path: directory.path }),
      });
    } catch (error) {
      console.error("erro ao criar pasta: ", error);
    }
  };

  const handleDownload = async (downloadFilename, downloadPath) => {
    const username = localStorage.getItem("username");
    const password = localStorage.getItem("password");
    const encodedCredentials = btoa(`${username}:${password}`);
    try {
      const response = await fetch(`http://${ip}:8080/downloadFile`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json", // Definindo o tipo de conteúdo como JSON
          Authorization: `Basic ${encodedCredentials}`, // Cabeçalho de autenticação
        },
        body: JSON.stringify({
          filename: downloadFilename,
          path: downloadPath,
        }),
      });

      if (!response.ok) throw new Error("Erro ao fazer o download");

      const blob = await response.blob();
      const link = document.createElement("a");
      link.href = URL.createObjectURL(blob);
      link.download = downloadFilename || "arquivo";
      link.click();
    } catch (error) {
      console.error("Erro no download:", error);
    }
  };

  const handleFileChange = (event) => {
    setFile(event.target.files[0]);
  };

  const handleSendFile = async () => {
    const username = localStorage.getItem("username");
    const password = localStorage.getItem("password");
    const encodedCredentials = btoa(`${username}:${password}`);

    if (!file) {
      alert("Por favor, selecione um arquivo.");
      return;
    }

    const formData = new FormData();
    formData.append("file", file);
    formData.append("name", file.name);
    formData.append("path", directory.path);

    try {
      const response = await fetch(`http://${ip}:8080/fileReceiver`, {
        method: "POST",
        headers: {
          Authorization: `Basic ${encodedCredentials}`, // Cabeçalho de autenticação
        },
        body: formData,
      });

      if (response.ok) {
        alert("Arquivo enviado com sucesso");
        setFile(null);
      }
      else alert("Falha ao enviar o arquivo");
    } catch (error) {
      console.error("Erro ao enviar o arquivo:", error);
      alert("Erro ao enviar o arquivo");
    }
  };


  const handleRename = async () => {
    const username = localStorage.getItem("username");
    const password = localStorage.getItem("password");
    const encodedCredentials = btoa(`${username}:${password}`);

    // Solicitar o novo nome do arquivo ou pasta
    const newName = prompt("Digite o novo nome para o arquivo ou pasta:");
    if (!newName) {
      alert("Nome não pode ser vazio!");
      return;
    }
    let oldPath = '';
    let newPath = '';
    if (contextMenu.item.type.localeCompare("file") == 0) {
      const extension = contextMenu.item.filename.split('.')[1];
      oldPath = directory.path + contextMenu.item.filename;  // Caminho antigo
      newPath = directory.path + newName + '.' + extension;    // Novo caminho
    }
    else {
      const extension = '';
      oldPath = directory.path + contextMenu.item.filename;
      newPath = directory.path + newName;
    }
    console.log(oldPath)
    // Enviar a solicitação de renomeação para o backend
    try {
      const response = await fetch(`http://${ip}:8080/renameFolder`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json", // Definir tipo de conteúdo
          Authorization: `Basic ${encodedCredentials}`, // Autenticação
        },
        body: JSON.stringify({
          oldpath: oldPath, // Caminho antigo
          newpath: newPath, // Novo caminho
        }),
      });

      if (response.ok) {
        alert("Arquivo ou pasta renomeado com sucesso!");
      } else {
        alert("Falha ao renomear o arquivo ou pasta.");
      }
    } catch (error) {
      console.error("Erro ao renomear:", error);
      alert("Erro ao renomear o arquivo ou pasta.");
    }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    const droppedFile = e.dataTransfer.files[0];
    if (droppedFile) {
      setFile(droppedFile);
    }
  };

  const handleDragOver = (e) => {
    e.preventDefault();
    e.stopPropagation();
  };

  return (
    <div className="main-container">
      <button className="logout" onClick={handleLogout}>Logout</button>
      <div className="left-column">
        <div className="header-container">
          <div className="button-container">
            <div className="return-button">
              <button onClick={handleReturnClick}>
                <BsArrowLeft size={15} />
              </button>
            </div>
            <div>
              <button onClick={handleCreateFolder}>
                <AiOutlinePlus size={15} />
              </button>
            </div>
          </div>

          <div className="directory-text">
            {directory.path.replace("../../..", "")}
          </div>
        </div>

        <div className="scrollable-container">
          {directory.files
            .filter((item) => {
              // Filtra os itens que NÃO satisfazem a condição
              return !(
                directory.path === "/compartilhado/" &&
                item.type === "folder" &&
                item.filename.startsWith("priv_") &&
                item.filename !== `priv_${localStorage.getItem("username")}`
              );
            })
            .map((item, index) => (
              <div
                key={index}
                className="item-container"
                onContextMenu={(e) => {
                  e.preventDefault();
                  handleItemClick(item, e);
                }}
                onClick={() => handleLeftClick(item)}
              >
                <img
                  src={item.type === "folder" ? file_upload : suinasLogo}
                  alt={item.type}
                  className="item-icon"
                />
                <span className="item-name">{item.filename}</span>
              </div>
            ))}
        </div>
      </div>

      {/* Context Menu */}
      {contextMenu.visible && (
        <div
          className="context-menu"
          style={{
            top: contextMenu.y,
            left: contextMenu.x,
            transform: "translate(-50%, -50%)",
          }}
          ref={contextMenuRef}
        >
          <ul>
            <li>
              <button
                onClick={() => {
                  handleDownload(contextMenu.item.filename, directory.path);
                  setContextMenu({ ...contextMenu, visible: false });
                  e.preventDefault();
                  // Close menu
                }}

              >
                Download
              </button>
            </li>
            <li>
              <button
                onClick={() => {
                  handleRename()
                  setContextMenu({ ...contextMenu, visible: false });
                  // e.preventDefault();
                  // Close menu
                }}
              >
                Rename
              </button>
            </li>
            <li>
              <button
                onClick={() => {
                  const confirmation = window.confirm(
                    "Are you sure you want to delete this file?"
                  );
                  if (confirmation) {
                    handleDelete()
                  }
                  setContextMenu({ ...contextMenu, visible: false });
                  e.preventDefault();
                  // Close menu
                }}
              >
                Delete
              </button>
            </li>
          </ul>
        </div>
      )}

      <div className="right-column">
        <div className="right-column-bottom">
          <div className="rectangle">
            <p>Available disk storage:<br /><br /> {directory.free_disk.toFixed(2)}%</p>
          </div>
        </div>
        <br />
        <div
          className="drag-drop-container"
          onDrop={handleDrop}
          onDragOver={handleDragOver}
        >
          <div className="drag-area">Drop a file here!</div>
          <br />
          <img
            src={file ? suinasLogo : file_upload}
            alt=""
            className="file-upload"
            onClick={() => document.getElementById("file-input").click()}
            style={{ cursor: "pointer" }}
          />
          <br />
          <input
            type="file"
            id="file-input"
            style={{ display: "none" }}
            onChange={handleFileChange}
          />
          <div className="send-file">
            <button onClick={handleSendFile}>Send File</button>
          </div>
        </div>
      </div>
    </div>
  );
}

export default Home;
