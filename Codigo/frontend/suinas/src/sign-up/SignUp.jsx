import React, { useState } from 'react';
import { login, register } from '../auth/authService';


function SignUp({ isSignUp, onLoginSuccess }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [errorMessage, setErrorMessage] = useState('');

  const handleSignUp = async () => {
    if (password !== confirmPassword) {
      setErrorMessage('Passwords do not match.');
      return;
    }
    try {
      await register(username, password);
      setErrorMessage('User registered successfully. You can now log in.');
    } catch (error) {
      setErrorMessage('Error registering user: ' + error.message);
    }
  };

  const handleLogin = async () => {
    try {
      await login(username, password);
      onLoginSuccess(username, password); // Notifica o App que o login foi bem-sucedido
    } catch (error) {
      setErrorMessage('Error logging in: ' + error.message);
    }
  };

  return (
    <div className={`background-${isSignUp ? 'signup' : 'login'}`}>
      <h1>{isSignUp ? 'Sign Up' : 'Login'}</h1>
      <div className="input-group">
        <label className="fields" htmlFor="username">Username</label><br />
        <input
          type="text"
          name="username"
          autoComplete="off"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
        />
      </div>
      <br />
      <div className="input-group">
        <label className="fields" htmlFor="password">Password</label><br />
        <input
          type="password"
          name="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />
      </div>
      <br />
      {isSignUp && (
        <div className="input-group">
          <label className="fields" htmlFor="confirm-password">Confirm Password</label><br />
          <input
            type="password"
            name="confirm-password"
            value={confirmPassword}
            onChange={(e) => setConfirmPassword(e.target.value)}
          />
        </div>
      )}
      <br />
      {errorMessage && <p className="error-message">{errorMessage}</p>}
      <button
        className={isSignUp ? 'create-button' : 'login-button'}
        onClick={isSignUp ? handleSignUp : handleLogin}
      >
        {isSignUp ? 'Create!' : 'Login!'}
      </button>
    </div>
  );
}

export default SignUp;
