import suinas_logo from './assets/suinas_logo.png';

function Header() {
  return (
    <header>
        <img className='logo' src={suinas_logo} alt="Suinas logo" />
        <hr />
    </header>
  );
}

export default Header;