const fs = require('fs');
let code = fs.readFileSync('src/components/Terminal.tsx', 'utf8');

code = code.replace("import { \n  X, Terminal as TerminalIcon, Play, RefreshCw, Copy, Check, \n  SquareTerminal, CirclePlay, LayoutDashboard, Database, Ghost\n} from 'lucide-react';", 
"import { \n  X, Terminal as TerminalIcon, Play, RefreshCw, Copy, Check, \n  SquareTerminal, CirclePlay, LayoutDashboard, Database, Ghost\n} from 'lucide-react';\nimport { ClearableInput } from './ClearableInput';");

const inputStart = code.lastIndexOf('<input');
const inputEnd = code.indexOf('/>', inputStart) + 2;

const newCode = `<ClearableInput
                  ref={inputRef}
                  type="text"
                  value={target}
                  onChange={e => setTarget(e.target.value)}
                  onKeyDown={handleKeyDown}
                  autoCapitalize="none"
                  autoComplete="off"
                  autoCorrect="off"
                  spellCheck={false}
                  placeholder={getPlaceholder(tool.id, tool.requiresInput)}
                  className="bg-[#050505] border border-neon-green/20 focus-within:border-neon-green rounded-xl text-xs sm:text-[13px]"
                  disabled={isRunning}
                  onClear={() => setTarget('')}
                />`;

code = code.substring(0, inputStart) + newCode + code.substring(inputEnd);

fs.writeFileSync('src/components/Terminal.tsx', code);
console.log('patched terminal');
