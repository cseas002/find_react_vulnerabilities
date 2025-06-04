import React from 'react';
import { Link } from 'react-scroll';
import './Navbar.css';

// Create a context for images
const image = require.context('./images', false, /\.(png|jpe?g|svg)$/);

const Navbar = () => {
  return (
    <nav className="navbar">
      <ul>
        <div className="navbar-link-group"> 
          <li><Link to="skills-marker" smooth={true} duration={500}>Skills</Link></li>
          <li><Link to="background-marker" smooth={true} duration={500}>Background</Link></li>
        </div>
        
        <li><Link to="home" smooth={true} duration={500}> <img src={image("./avatar.png")} className="avatar" alt="avatar"/></Link></li>
        <div className="navbar-link-group"> 
          <li><Link to="projects" smooth={true} duration={500}>Projects</Link></li>
          <li><Link to="contact" smooth={true} duration={500}>Contact</Link></li>
        </div>
      </ul>
    </nav>
  );
};

export default Navbar;
