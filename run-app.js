const http = require('http');
const fs = require('fs');
const path = require('path');
const { handleServerlessCall } = require('./api/src/functions/status.js');

const server = http.createServer((req, res) => {
    if (req.url.startsWith('/api/status')) {
        return handleServerlessCall(req, res);
    }
    
    let filePath = path.join(__dirname, 'src', req.url === '/' ? 'index.html' : req.url);
    fs.readFile(filePath, (err, content) => {
        if (err) {
            res.writeHead(404, { 'Content-Type': 'text/plain' });
            res.end('Not Found');
        } else {
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end(content);
        }
    });
});

server.listen(8080, () => {
    console.log('\n======================================================');
    console.log('App Successfully Repaired & Local Proxy Gateway Booted!');
    console.log('Open this URL in your web browser: http://localhost:8080');
    console.log('======================================================\n');
});
