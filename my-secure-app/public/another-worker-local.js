self.onmessage = function (e) {
    console.log('Another Worker (Local): Message received from main script - ', e.data);
    const result = e.data + ' - Processed by Another Worker (Local)';
    console.log('Another Worker (Local): Posting message back to main script - ', result);
    self.postMessage(result);
}; 