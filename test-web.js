const http = require('http');
const WebSocket = require('ws');

const server = http.createServer((req, res) => {
  let body = [];
  req.on('data', chunk => body.push(chunk));
  req.on('end', () => {
    body = Buffer.concat(body).toString();

    const requestInfo = {
      time: new Date().toISOString(),
      method: req.method,
      url: req.url,
      ip: req.socket.remoteAddress,
      headers: req.headers,
      body: body || null
    };

    console.log(requestInfo);

    wss.clients.forEach(client => {
      if (client.readyState === WebSocket.OPEN) {
        client.send(JSON.stringify(requestInfo, null, 2));
      }
    });

    if (req.url === '/') {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(`
        <!DOCTYPE html>
        <html>
        <head>
          <title>Live Request Logger</title>
          <style>
            body { background: #111; color: #0f0; font-family: monospace; padding: 10px; }
            pre { white-space: pre-wrap; word-break: break-word; }
          </style>
        </head>
        <body>
          <h1>Live Request Logger</h1>
          <div id="log"></div>
          <script>
            const logDiv = document.getElementById('log');
            const ws = new WebSocket('ws://' + location.host);
            ws.onmessage = (event) => {
              const data = JSON.parse(event.data);
              const info = 
                \`[\${data.time}] \${data.method} \${data.url} from \${data.ip}\\n\` +
                \`User-Agent: \${data.headers['user-agent'] || 'N/A'}\\n\` +
                \`Headers: \${JSON.stringify(data.headers, null, 2)}\\n\` +
                (data.body ? 'Body: ' + data.body + '\\n' : '') +
                '----------------------\\n';
              logDiv.innerHTML += '<pre>' + info + '</pre>';
              logDiv.scrollTop = logDiv.scrollHeight;
            };
            ws.onopen = () => console.log('Connected to server');
          </script>
        </body>
        </html>
      `);
    } else {
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.end('Request received\n');
    }
  });
});

const wss = new WebSocket.Server({ server });

wss.on('connection', ws => {
  ws.send(JSON.stringify({ time: new Date().toISOString(), message: 'Connected to live logger' }));
});

const PORT = 3000;
server.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));
