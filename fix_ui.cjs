const fs = require('fs');
let content = fs.readFileSync('src/views/ScannerTools.tsx', 'utf8');

content = content.replace(/className="p-4 flex flex-col gap-6"/g, 'className="flex flex-col gap-4 sm:gap-6"');

content = content.replace(/className="bg-\[#050505\] border-l-4 border-l-neon-green border-y border-r border-neon-green\/20 rounded-r-lg p-5 flex flex-col gap-5"/g, 'className="bg-[#050505] border-l-4 border-l-neon-green border-y border-r border-neon-green/20 rounded-r-lg p-4 sm:p-5 flex flex-col gap-4 sm:gap-5"');

content = content.replace(/<div className="flex gap-3 items-center">\n\s*<input/g, '<div className="flex flex-col sm:flex-row gap-3 sm:items-center">\n            <input');

content = content.replace(/<button \n              onClick=\{status === 'running' \? \(\) => setStatus\('finished'\) : execute\}\n              className="bg-neon-green text-black border border-neon-green rounded px-6 py-3 hover:bg-neon-green hover:shadow-\[0_0_15px_rgba\(57,255,20,0\.5\)\] transition-all flex items-center justify-center font-bold"/g, '<button \n              onClick={status === \'running\' ? () => setStatus(\'finished\') : execute}\n              className="w-full sm:w-auto bg-neon-green text-black border border-neon-green rounded px-6 py-3 hover:bg-neon-green hover:shadow-[0_0_15px_rgba(57,255,20,0.5)] transition-all flex items-center justify-center font-bold"');

fs.writeFileSync('src/views/ScannerTools.tsx', content);
console.log("Done");
