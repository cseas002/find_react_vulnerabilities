import logo from './logo.svg';
import './App.css';
import ExternalContent from './ExternalContent';

function App() {
  return (
    <div className="App">
      <header className="App-header">
        <img src={logo} className="App-logo" alt="logo" />
        <p>
          Edit <code>src/App.js</code> and save to reload.
        </p>
        <a
          className="App-link"
          href="https://reactjs.org"
          target="_blank"
          rel="noopener noreferrer"
        >
          Learn React
        </a>
        <img
          src="https://picsum.photos/200/300"
          alt="Random placeholder"
          style={{ marginTop: '20px', borderRadius: '8px' }}
        />
      </header>
      <ExternalContent />
    </div>
  );
}

export default App;
