import React from 'react';
import Navbar from './components/Navbar';
import Animation from './components/Animation';
import Connect from './components/Connect';
import Skills from './components/Skills';
import Background from './components/Background';
import Projects from './components/Projects';
import Contact from './components/Contact';
import './App.css';

function App() {
  return (
    <div className="App">
      <Navbar />
      <Home />      
      <Skills />
      <Background />
      <Projects />
      <Contact />
    </div>
  );
}

const Home = () => (
  <div className="home section" id="home">
    <div className="home-content">
      <div className="summary align-right">
        <div className="summary-content">
          
          <h1>
            Hi, I'm Template Man...!
          </h1>
          <p>
            Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged.
          </p>
          
          <Connect linkedin="http://www.linkedin.com" github="https://github.com" contact="contact"
          resume="https://docs.google.com/document/d/1EujuYFWxVXZ2PUaJ2uizvK5raMoMsz1KMys-UYpUSk4/edit"/>
          
        </div>
      </div>
      <Animation fileName="home.json"/>
    </div>
    <div id="skills-marker"/>
  </div>
);



export default App;
