const fs = require('fs');
let code = fs.readFileSync('server.ts', 'utf8');

const startIdx = code.indexOf('// 20. CVE Lookup Proxy');
const endIdx = code.indexOf('app.listen(PORT, \'0.0.0.0\'');

if (startIdx !== -1 && endIdx !== -1) {
    const chunk = code.substring(startIdx, endIdx);
    code = code.replace(chunk, '');
    code = code.replace('// --- VITE DEV SERVER OR PROD STATIC ---', chunk + '\n// --- VITE DEV SERVER OR PROD STATIC ---');
    fs.writeFileSync('server.ts', code);
    console.log("Moved CVE endpoints.");
} else {
    console.log("Not found.");
}
