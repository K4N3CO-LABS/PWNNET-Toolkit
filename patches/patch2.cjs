const fs = require('fs');
let code = fs.readFileSync('server.ts', 'utf8');
const target = `     const phoneRegex = /(?:\\+?\\d{1,3}[-.\\s]?)?\\(?\\d{3}\\)?[-.\\s]?\\d{3}[-.\\s]?\\d{4}/g;\n     const matches = text.match(phoneRegex) || [];\n     const uniqueMatches = [...new Set(matches.map(m => m.trim()))].filter(m => m.length >= 10);`;
const rep = `     const phoneRegex = /(?<!\\\\d)(?:\\\\+?\\\\d{1,3}[-.\\\\s]?)?\\\\(?\\\\d{3}\\\\)?[-.\\\\s]?\\\\d{3}[-.\\\\s]?\\\\d{4}(?!\\\\d)/g;
     const matches = text.match(phoneRegex) || [];
     const uniqueMatches = [...new Set(matches.map(m => m.trim()))].filter(m => {
        const digits = m.replace(/\\\\D/g, '').length;
        return digits >= 10 && digits <= 15;
     });`;
code = code.replace(target, rep);
fs.writeFileSync('server.ts', code);
