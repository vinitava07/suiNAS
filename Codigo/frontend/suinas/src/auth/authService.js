const baseIP = "http://localhost:8080";

// const authService = {
//   login: async (usuario, senha) => {
//     try {
//       const response = await fetch(`${baseIP}/login`, {
//         method: "POST",
//         headers: {
//           "Content-Type": "application/json",
//         },
//         body: JSON.stringify({ usuario, senha }),
//       });

//       if (!response.ok) {
//         throw new Error("Login failed. Please check your credentials.");
//       }

//       const data = await response.json();
//       return data; // Ex: token ou informações do usuário
//     } catch (error) {
//       console.error("Error during login:", error);
//       throw error;
//     }
//   },

//   register: async (usuario, senha) => {
//     try {
//       const response = await fetch(`${baseIP}/register`, {
//         method: "POST",
//         headers: {
//           "Content-Type": "application/json",
//         },
//         body: JSON.stringify({ usuario, senha }),
//       });

//       if (!response.ok) {
//         throw new Error("Registration failed. Please try again.");
//       }

//       const data = await response.json();
//       return data; // Ex: mensagem de sucesso ou dados do usuário criado
//     } catch (error) {
//       console.error("Error during registration:", error);
//       throw error;
//     }
//   },

//   deleteUser: async (id) => {
//     try {
//       const response = await fetch(`${baseIP}/delete`, {
//         method: "POST",
//         headers: {
//           "Content-Type": "application/json",
//         },
//         body: JSON.stringify({ id }),
//       });

//       if (!response.ok) {
//         throw new Error("Failed to delete user. Please try again.");
//       }

//       const data = await response.json();
//       return data; // Ex: mensagem de sucesso
//     } catch (error) {
//       console.error("Error during user deletion:", error);
//       throw error;
//     }
//   },
// };

// export default authService;

export const login = async (usuario, senha) => {
  try {
    const response = await fetch(`${baseIP}/login`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ usuario, senha }),
    });

    if (!response.ok) {
      throw new Error("Login failed. Please check your credentials.");
    }

    return true;
  } catch (error) {
    console.error("Error during login:", error);
    throw error;
  }
};

export const register = async (usuario, senha) => {
  try {
    const response = await fetch(`${baseIP}/register`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ usuario, senha }),
    });

    if (!response.ok) {
      throw new Error("Registration failed. Please try again.");
    }

    return true;
  } catch (error) {
    console.error("Error during registration:", error);
    throw error;
  }
};

export const checkLoginStatus = () => {
  // Verifica se o usuário está logado
  return localStorage.getItem("isLoggedIn") === "true";
};

export const logout = () => {
  localStorage.removeItem("isLoggedIn");
  localStorage.removeItem("username");
  localStorage.removeItem("senha");
  window.location.reload(); // Recarrega a página pra deslogar
};
