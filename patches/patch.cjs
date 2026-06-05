const fs = require('fs');
let content = fs.readFileSync('src/views/ScannerTools.tsx', 'utf8');
const target = `<div className="text-xs font-mono flex flex-col gap-1 text-gray-400 uppercase tracking-widest">
              <div>Found <span className="mx-2">/</span> <span className="text-white">{results.length}</span></div>
              <div>Status <span className="mx-2">/</span> <span className={status === 'running' ? 'text-neon-green animate-pulse' : 'text-white'}>{status === 'running' ? 'SCANNING' : status === 'finished' ? 'COMPLETE' : 'STANDBY'}</span></div>
            </div>
          </div>`;
          
const replacement = `<div className="text-xs font-mono flex flex-col gap-1 text-gray-400 uppercase tracking-widest">
              <div>Found <span className="mx-2">/</span> <span className="text-white">{results.length}</span></div>
              <div>Status <span className="mx-2">/</span> <span className={status === 'running' ? 'text-neon-green animate-pulse' : 'text-white'}>{status === 'running' ? 'SCANNING' : status === 'finished' ? 'COMPLETE' : 'STANDBY'}</span></div>
            </div>
            {results.length > 0 && <button onClick={() => setResults([])} className="bg-black hover:bg-neon-green/10 border border-red-500/30 text-gray-400 hover:text-red-400 px-4 py-2 rounded text-[10px] font-bold uppercase tracking-widest transition-all">Clear</button>}
          </div>`;

content = content.split(target).join(replacement);
fs.writeFileSync('src/views/ScannerTools.tsx', content);
