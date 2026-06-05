import { useState, useEffect } from 'react';
import { 
  Database, Scroll, ShieldAlert, CheckCircle, AlertTriangle, 
  Terminal, ExternalLink, Calendar, Filter, FileCode2
} from 'lucide-react';
import { motion } from 'motion/react';
import { logService, LogEntry } from '../utils/logger';

export function Logbook() {
  const [selectedLogsCategory, setSelectedLogsCategory] = useState<string>('ALL');
  const [activeLogId, setActiveLogId] = useState<string | null>(null);
  const [logs, setLogs] = useState<LogEntry[]>([]);

  useEffect(() => {
    const unsubscribe = logService.subscribe((updatedLogs) => {
      setLogs([...updatedLogs]);
    });
    return () => { unsubscribe(); };
  }, []);

  const getStatusColor = (status: LogEntry['status']) => {
    switch (status) {
      case 'OK': return 'text-green-400 bg-green-500/10 border-green-500/30';
      case 'WARN': return 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30';
      case 'FAIL': return 'text-red-400 bg-red-500/10 border-red-500/30';
      case 'SYSTEM': return 'text-[#38bdf8] bg-sky-500/10 border-sky-500/30';
    }
  };

  const filteredLogs = selectedLogsCategory === 'ALL' 
    ? logs 
    : logs.filter(log => log.status === selectedLogsCategory || log.module === selectedLogsCategory);

  return (
    <div className="flex-1 flex flex-col overflow-hidden bg-obsidian relative">
      {/* CRT scanline effect */}
      <div className="absolute inset-0 pointer-events-none bg-[linear-gradient(rgba(18,16,16,0)+50%,rgba(0,0,0,0.25)+50%),linear-gradient(90deg,rgba(255,0,0,0.06),rgba(0,255,0,0.02),rgba(0,0,255,0.06))] bg-[size:100%_4px,6px_100%] z-10 opacity-30"></div>

      {/* Control filter tags */}
      <div className="p-4 bg-[#0a0a0a] border-b border-border-gray flex flex-col gap-2 shrink-0">
        <div className="text-[10px] font-mono text-gray-400 flex items-center gap-1.5 uppercase">
          <Database size={11} className="text-[#38bdf8]" />
          <span>Security Operations Center Log Audit Registry</span>
        </div>
        
        <div className="flex items-center gap-1.5 overflow-x-auto pb-1 text-xs">
          {['ALL', 'OK', 'WARN', 'FAIL', 'SYSTEM'].map((cat) => (
            <button
              key={cat}
              onClick={() => {
                setSelectedLogsCategory(cat);
                setActiveLogId(null);
              }}
              className={`px-3 py-1 text-[10px] font-mono transition-colors uppercase border rounded-xl ${
                selectedLogsCategory === cat
                  ? 'bg-neon-green text-black border-neon-green font-bold'
                  : 'bg-black text-gray-400 border-border-gray hover:text-neon-green hover:border-gray-550'
              }`}
            >
              {cat}
            </button>
          ))}
          <div className="flex-1"></div>
          <button
            onClick={() => logService.clearLogs()}
            className="px-3 py-1 text-[10px] font-mono transition-colors uppercase border rounded-xl bg-red-950/30 text-red-400 border-red-900 hover:bg-red-900/50"
          >
            Clear Activity
          </button>
        </div>
      </div>

      {/* Logs output list */}
      <div className="flex-1 overflow-y-auto p-4 space-y-2.5 pb-28">
        {filteredLogs.map((log) => (
          <div 
            key={log.id}
            className={`border transition-all duration-300 bg-[#0c0c0c]/90 rounded-2xl overflow-hidden ${
              activeLogId === log.id 
                ? 'border-neon-green/60 bg-neon-green/[0.02] shadow-[0_0_15px_rgba(0,255,65,0.06)] scale-[1.01]' 
                : 'border-neon-green/10 hover:border-[#38bdf8]/40 hover:bg-[#0f0f0f]/80'
            }`}
          >
            {/* Header row */}
            <div 
              onClick={() => setActiveLogId(activeLogId === log.id ? null : log.id)}
              className="p-3.5 flex justify-between items-center cursor-pointer select-none text-[11px] font-mono"
            >
              <div className="flex items-center gap-3">
                <span className={`px-2 py-0.5 border text-[8px] font-black rounded-full select-none ${getStatusColor(log.status)}`}>
                  {log.status}
                </span>
                <span className="text-gray-500 font-bold">{log.time}</span>
                <span className="text-[#38bdf8] font-bold font-mono tracking-wider">[{log.module}]</span>
                <span className="text-gray-200 line-clamp-1 font-sans font-medium hover:text-white transition-colors">{log.event}</span>
              </div>
              <div className="text-gray-400 hover:text-neon-green text-[9px] uppercase font-mono tracking-wider font-extrabold select-none">
                {activeLogId === log.id ? '[COLLAPSE]' : '[DETAILS]'}
              </div>
            </div>

            {/* Expandable details segment */}
            {activeLogId === log.id && (
              <motion.div 
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: 'auto' }}
                className="px-4 pb-4 pt-2 border-t border-neon-green/20 bg-black/80 text-[11px] font-mono text-gray-300 space-y-2"
              >
                <div className="flex justify-between border-b border-neon-green/5 pb-1">
                  <span className="text-gray-500 uppercase text-[9px] font-bold">Event identifier:</span>
                  <span className="text-neon-green font-bold">{log.id}</span>
                </div>
                <div className="flex justify-between border-b border-neon-green/5 pb-1">
                  <span className="text-gray-500 uppercase text-[9px] font-bold">Target address:</span>
                  <span className="text-white font-bold inline-flex items-center gap-1">
                    {log.target}
                    <Terminal size={10} className="text-[#38bdf8]" />
                  </span>
                </div>
                <div>
                  <div className="text-gray-500 uppercase text-[9px] font-bold mb-1">Raw audit report:</div>
                  <div className="bg-[#050505] border border-neon-green/10 p-3 text-[10px] text-gray-300 whitespace-pre-wrap leading-relaxed rounded-xl font-mono">
                    {log.details}
                  </div>
                </div>
              </motion.div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
