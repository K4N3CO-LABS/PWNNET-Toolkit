const fs = require('fs');
let code = fs.readFileSync('server.ts', 'utf8');
code = code.replace("const phoneRegex = /(?<!\\\\d)(?:\\\\+?\\\\d{1,3}[-.\\\\s]?)?\\\\(?\\\\d{3}\\\\)?[-.\\\\s]?\\\\d{3}[-.\\\\s]?\\\\d{4}(?!\\\\d)/g;", "const phoneRegex = /(?<!\\d)(?:\\+?\\d{1,3}[-.\\s]?)?\\(?\\d{3}\\)?[-.\\s]?\\d{3}[-.\\s]?\\d{4}(?!\\d)/g;");
code = code.replace("const digits = m.replace(/\\\\D/g, '').length;", "const digits = m.replace(/\\D/g, '').length;");
fs.writeFileSync('server.ts', code);
