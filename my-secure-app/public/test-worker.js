// my-secure-app/public/test-worker.js
self.onmessage = function (e) {
    console.log('Worker: Message received from main script - ', e.data);
    const result = 'Worker: Processed - ' + String(e.data).toUpperCase();
    console.log('Worker: Posting message back to main script - ', result);
    self.postMessage(result);
};

self.onerror = function (e) {
    console.error('Worker: Error in worker:', e);
};

console.log('Worker: test-worker.js script loaded and running.'); 