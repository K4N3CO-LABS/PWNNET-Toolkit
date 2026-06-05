const fs = require('fs');

function patchFile(file, importLoc, importStr, stateVarRegex) {
  let code = fs.readFileSync(file, 'utf8');
  if (!code.includes('ClearableInput')) {
     const p = code.indexOf(importLoc);
     code = code.substring(0, p) + importStr + '\n' + code.substring(p);
  }

  // we need to replace <input ... />
  // some are multiline, so we match `<input [\s\S]*?\/>`
  code = code.replace(/<input([\s\S]*?)\/>/g, (match, body) => {
     // Don't replace input type="range"
     if (body.includes('type="range"')) return match;

     // Extract value prop: value={someVar} -> setSomeVar('')
     const valMatch = body.match(/value=\{([a-zA-Z0-9_]+)\}/);
     let setFunc = '';
     if (valMatch) {
       const v = valMatch[1];
       // Assume setVar rule: setUrl, setTarget, setIp, etc.
       setFunc = 'set' + v.charAt(0).toUpperCase() + v.slice(1);
     }
     
     // Remove old className, we let ClearableInput handle width, we just pass the wrapper className
     body = body.replace(/className="[^"]*"/, 'className="bg-[#050505] border border-neon-green/20 focus-within:border-neon-green rounded-xl text-xs"');

     let onClearStr = '';
     if (setFunc) {
       onClearStr = ` onClear={() => ${setFunc}('')}`;
     }
     
     // In CustomTools, the QR tool might use setInputVal
     if (body.includes('setInputVal(')) {
        onClearStr = ` onClear={() => setInputVal('')}`;
     }
     if (body.includes('setSecret(')) {
        onClearStr = ` onClear={() => {setSecret(''); setResult(null); }}`;
     }
     if (body.includes('setIp(')) {
        onClearStr = ` onClear={() => {setIp(''); setResult(null); }}`;
     }
      if (body.includes('setCveId(')) {
        onClearStr = ` onClear={() => setCveId('')}`;
     }

     return `<ClearableInput${body}${onClearStr} />`;
  });

  fs.writeFileSync(file, code);
  console.log('patched ' + file);
}

patchFile('src/views/ScannerTools.tsx', "import { ToolDef }", "import { ClearableInput } from '../components/ClearableInput';");
patchFile('src/views/CustomTools.tsx', "import { ToolDef }", "import { ClearableInput } from '../components/ClearableInput';");
