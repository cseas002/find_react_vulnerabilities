import React, { useEffect } from 'react';
import './external-fonts.css'; // Import the new CSS file

function ExternalContent() {
    useEffect(() => {
        fetch('https://jsonplaceholder.typicode.com/todos/1')
            .then(response => response.json())
            .then(json => console.log('Fetched data:', json))
            .catch(error => console.error('Error fetching data:', error));

        // Worker tests
        try {
            console.log('Main: Attempting to load local worker /test-worker.js');
            const localWorker = new Worker('/test-worker.js');
            localWorker.postMessage('Hello Local Worker');
            localWorker.onmessage = (e) => {
                console.log('Main: Message received from local worker:', e.data);
                localWorker.terminate();
            };
            localWorker.onerror = (e) => {
                console.error('Main: Error with local worker:', e.filename, e.lineno, e.message);
                localWorker.terminate();
            };
        } catch (e) {
            console.error("Main: Failed to create local worker:", e);
        }

        try {
            console.log('Main: Attempting to load external worker from https://cdn.example.com/another-worker.js');
            const externalWorker = new Worker('https://cdn.example.com/another-worker.js');
            externalWorker.postMessage("Hello External Worker");
            externalWorker.onmessage = (e) => {
                console.log('Main: Message received from external worker:', e.data);
                externalWorker.terminate();
            };
            externalWorker.onerror = (e) => {
                console.error('Main: Error with external worker:', e.filename, e.lineno, e.message);
                externalWorker.terminate();
            };
        } catch (e) {
            console.error("Main: Failed to create external worker:", e);
        }

    }, []);

    return (
        <div style={{ border: '2px solid orange', padding: '10px', marginTop: '20px' }}>
            <h3>External Content Tester</h3>

            <h4>Iframe Test (frame-src)</h4>
            <iframe
                src="https://www.example.com"
                title="Example Iframe"
                width="300"
                height="150"
                style={{ border: '1px solid #ccc' }}
            ></iframe>

            <h4>Form Action Test (form-action)</h4>
            <form action="https://httpbin.org/post" method="POST" target="_blank">
                <label htmlFor="testInput">Test Input: </label>
                <input type="text" id="testInput" name="testInput" defaultValue="Hello CSP" />
                <button type="submit">Submit to httpbin.org</button>
            </form>

            <h4>Font Test (font-src)</h4>
            <p className="external-font-text">This text should use the external RobotoTest font.</p>

            <h4>Object Test (object-src)</h4>
            <object data="https://www.example.com/test.swf" type="application/x-shockwave-flash" width="300" height="120">
                <param name="movie" value="https://www.example.com/test.swf" />
                <p>Alternative content: Your browser does not support displaying SWF files. (This is for CSP testing of object-src).</p>
            </object>

            <h4>Worker Test (worker-src)</h4>
            <p>Attempted to load a local worker from /test-worker.js (check console).</p>
            <p>Attempted to load an external worker from cdn.example.com (check console).</p>

            <p style={{ marginTop: '10px' }}>
                <em>(A fetch call to jsonplaceholder.typicode.com was made on component mount - check console)</em>
            </p>
        </div>
    );
}

export default ExternalContent; 