const fs = require('fs');
let code = fs.readFileSync('server.ts', 'utf8');

const regex = /app\.get\('\/api\/net\/cve\/recent', async \(req, res\) => \{/;
code = code.replace(regex, "app.get('/api/net/cve/recent', async (req, res) => {\n  console.log('HIT RECENT API ENDPOINT!!!');\n");

fs.writeFileSync('server.ts', code);
console.log('patched log');
