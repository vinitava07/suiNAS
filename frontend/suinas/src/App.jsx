import './App.css';
import './index.css';
import './sign-up/SignUp.css';
import Header from './Header';
import SignUp from './sign-up/SignUp';
import Home from './home/Home';
import { useState, useEffect } from 'react';
import { checkLoginStatus, logout } from './auth/authService';

function App() {
  const [logged, setLogged] = useState(false);
  const [isSignUp, setIsSignUp] = useState(true); // Controle do estado Sign Up/Login

  useEffect(() => {
    // Verifica se o usuário já está logado
    const status = checkLoginStatus();
    setLogged(status);
  }, []);

  // const handleLogout = () => {
  //   logout();
  //   setLogged(false);
  // };

  const handleLoginSuccess = (username, password) => {
    localStorage.setItem("isLoggedIn", "true")
    localStorage.setItem("username", username)
    localStorage.setItem("password", password)
    setLogged(true);
  };

  if (logged) {
    return (
      <>
        <Header />
        <Home />
      </>
    );
  }

  return (
    <>
      <Header />
      <br />
      <div className="signup-container">
        <button className='sign-up-socorro' onClick={() => setIsSignUp(true)}>Sign Up</button>
        <button className='login-socorro' onClick={() => setIsSignUp(false)}>Login</button>
        <SignUp isSignUp={isSignUp} onLoginSuccess={handleLoginSuccess} />
      </div>
    </>
  );
}

export default App;
