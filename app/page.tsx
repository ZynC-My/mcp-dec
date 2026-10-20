'use client';
import { useState, useRef, useCallback } from 'react';

type Lang = 'auto' | 'lua' | 'cs' | 'cpp';
type OutTab = 'pseudo' | 'disasm' | 'il' | 'strings' | 'hex';

interface DecompileResult {
  language: string;
  detected: string;
  pseudo: string;
  disasm?: string;
  il?: string;
  strings?: string[];
  hexPreview?: string;
  stats: { functions: number; instructions: number; strings: number; size: number };
  error?: string;
}

const LANGS: { id: Lang; label: string }[] = [
  { id: 'auto', label: 'Auto-detect' },
  { id: 'lua', label: 'Lua / LuaJIT' },
  { id: 'cs', label: 'C# (.NET)' },
  { id: 'cpp', label: 'C++ (native)' },
];

export default function Home() {
  const [lang, setLang] = useState<Lang>('auto');
  const [file, setFile] = useState<File | null>(null);
  const [drag, setDrag] = useState(false);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<DecompileResult | null>(null);
  const [error, setError] = useState('');
  const [tab, setTab] = useState<OutTab>('pseudo');
  const inputRef = useRef<HTMLInputElement>(null);

  const onDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault(); setDrag(false);
    const f = e.dataTransfer.files?.[0];
    if (f) { setFile(f); setResult(null); setError(''); }
  }, []);

  const analyze = async () => {
    if (!file) return;
    setLoading(true); setError(''); setResult(null);
    try {
      const buf = await file.arrayBuffer();
      const b64 = btoa(new Uint8Array(buf).reduce((d, b) => d + String.fromCharCode(b), ''));
      const res = await fetch('/api/decompile', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ filename: file.name, data: b64, lang }),
      });
      const json = await res.json();
      if (!res.ok) throw new Error(json.error || 'Decompilation failed');
      setResult(json);
      setTab(json.il ? 'il' : 'pseudo');
    } catch (e: any) { setError(e.message); }
    setLoading(false);
  };

  const copy = (t: string) => navigator.clipboard.writeText(t);

  return (
    <div className="container">
      <header>
        <div className="logo">Decompiler<span>Pro</span></div>
        <div className="badge">Lua 5.1–5.4 · LuaJIT · .NET IL · x86-64</div>
      </header>

      <div className="lang-row">
        {LANGS.map(l => (
          <button key={l.id} className={`lang-chip ${lang === l.id ? 'active' : ''}`} onClick={() => setLang(l.id)}>
            {l.label}
          </button>
        ))}
      </div>

      <div className={`dropzone ${drag ? 'drag' : ''}`}
        onClick={() => inputRef.current?.click()}
        onDragOver={e => { e.preventDefault(); setDrag(true); }}
        onDragLeave={() => setDrag(false)}
        onDrop={onDrop}>
        <div className="big">{file ? file.name : 'Drop binary here'}</div>
        <p>{file ? `${(file.size/1024).toFixed(1)} KB — click Analyze` : '.lua · .luac · .jit · .exe · .dll · .so · .elf · .bin'}</p>
        <input ref={inputRef} type="file" hidden onChange={e => { const f = e.target.files?.[0]; if (f) { setFile(f); setResult(null); setError(''); } }} />
      </div>

      {file && <button className="lang-chip" style={{marginTop:16, padding:'10px 24px', fontSize:14}} onClick={analyze} disabled={loading}>
        {loading ? 'Analyzing…' : '▶ Analyze'}
      </button>}

      {error && <div className="err">{error}</div>}

      {result && (
        <>
          <div className="stats">
            <div className="stat">Detected<b>{result.detected}</b></div>
            <div className="stat">Functions<b>{result.stats.functions}</b></div>
            <div className="stat">Instructions<b>{result.stats.instructions}</b></div>
            <div className="stat">Strings<b>{result.stats.strings}</b></div>
          </div>
          <div className="grid">
            <div className="panel">
              <div className="panel-head">
                <div className="tabs">
                  {result.il && <div className={`tab ${tab==='il'?'active':''}`} onClick={()=>setTab('il')}>IL / Bytecode</div>}
                  {result.disasm && <div className={`tab ${tab==='disasm'?'active':''}`} onClick={()=>setTab('disasm')}>Disassembly</div>}
                  <div className={`tab ${tab==='pseudo'?'active':''}`} onClick={()=>setTab('pseudo')}>Decompiled</div>
                </div>
                <button className="copy-btn" onClick={()=>copy(tab==='il'?(result.il||''):tab==='disasm'?(result.disasm||''):result.pseudo)}>copy</button>
              </div>
              <div className="panel-body">{tab==='il'?(result.il||result.disasm):tab==='disasm'?(result.disasm||result.il):result.pseudo}</div>
            </div>
            <div className="panel">
              <div className="panel-head">
                <div className="tabs">
                  <div className={`tab ${tab==='strings'?'active':''}`} onClick={()=>setTab('strings')}>Strings</div>
                  <div className={`tab ${tab==='hex'?'active':''}`} onClick={()=>setTab('hex')}>Hex</div>
                </div>
                <button className="copy-btn" onClick={()=>copy(tab==='strings'?(result.strings||[]).join('\n'):result.hexPreview||'')}>copy</button>
              </div>
              <div className="panel-body">{tab==='strings' ? (result.strings||[]).join('\n') : result.hexPreview}</div>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
