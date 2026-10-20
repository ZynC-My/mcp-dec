
import { u8, u32, u64, ascii, hexDump, extractStrings } from './format';

// ── opcode tables ──
const LUA51_OPS = ['MOVE','LOADK','LOADBOOL','LOADNIL','GETUPVAL','GETGLOBAL','GETTABLE','SETGLOBAL','SETUPVAL','SETTABLE','NEWTABLE','SELF','ADD','SUB','MUL','DIV','MOD','POW','UNM','NOT','LEN','CONCAT','JMP','EQ','LT','LE','TEST','TESTSET','CALL','TAILCALL','RETURN','FORLOOP','FORPREP','TFORLOOP','SETLIST','CLOSE','CLOSURE','VARARG'];
const LUA53_OPS = ['MOVE','LOADK','LOADKX','LOADBOOL','LOADNIL','GETUPVAL','GETTABUP','GETTABLE','SETTABUP','SETUPVAL','SETTABLE','NEWTABLE','SELF','ADD','SUB','MUL','DIV','MOD','POW','IDIV','BAND','BOR','BXOR','SHL','SHR','UNM','BNOT','NOT','LEN','CONCAT','JMP','EQ','LT','LE','EQK','EQI','LTI','LEI','GTI','GEI','TEST','TESTSET','CALL','TAILCALL','RETURN','RETURN0','RETURN1','FORLOOP','FORPREP','TFORPREP','TFORCALL','TFORLOOP','SETLIST','CLOSURE','VARARG','VARARGPREP','EXTRAARG'];
const LUA54_OPS = ['MOVE','LOADI','LOADF','LOADK','LOADKX','LOADFALSE','LFALSESKIP','LOADTRUE','LOADNIL','GETUPVAL','GETTABUP','GETTABLE','GETI','GETFIELD','SETTABUP','SETUPVAL','SETTABLE','SETI','SETFIELD','NEWTABLE','SELF','ADDI','ADDK','SUBK','MULK','MODK','POWK','DIVK','IDIVK','BANDK','BORK','BXORK','SHRI','SHLI','ADD','SUB','MUL','MOD','POW','DIV','IDIV','BAND','BOR','BXOR','SHL','SHR','UNM','BNOT','NOT','LEN','CONCAT','JMP','EQ','LT','LE','EQK','EQI','LTI','LEI','GTI','GEI','TEST','TESTSET','CALL','TAILCALL','RETURN','RETURN0','RETURN1','FORLOOP','FORPREP','TFORPREP','TFORCALL','TFORLOOP','SETLIST','CLOSURE','VARARG','VARARGPREP','EXTRAARG'];

interface LuaHeader { version: number; format: number; littleEndian: boolean; intSize: number; sizetSize: number; instrSize: number; luaNumSize: number; integral: boolean; jit: boolean; }
interface LuaConst { type: string; value: any; }
interface LuaInstr { pc: number; opcode: number; a: number; b: number; c: number; bx: number; sbx: number; }
interface LuaProto { name: string; linedefined: number; lastlinedefined: number; numparams: number; is_vararg: number; maxstacksize: number; code: LuaInstr[]; constants: LuaConst[]; upvalues: {name: string; instack: number; idx: number}[]; protos: LuaProto[]; lineinfo: number[]; }

class Reader {
  pos = 0;
  constructor(private d: Uint8Array, private h: LuaHeader) {}
  byte() { return u8(this.d, this.pos++); }
  u32() { const v = u32(this.d, this.pos); this.pos += 4; return v; }
  sizeT() { let v = 0; for (let i = 0; i < this.h.sizetSize; i++) v |= this.d[this.pos++] << (8*i); return v >>> 0; }
  int() { let v = 0; for (let i = 0; i < this.h.intSize; i++) v |= this.d[this.pos++] << (8*i); return v | 0; }
  num(): number {
    if (this.h.luaNumSize === 8) { const v = u64(this.d, this.pos); this.pos += 8; return Number(v); }
    const v = u32(this.d, this.pos); this.pos += 4; return v;
  }
  str(): string {
    const size = this.h.version >= 0x54 ? this.byte() : this.sizeT();
    if (size === 0) return '';
    const s = ascii(this.d, this.pos, size - 1); this.pos += size - 1; return s;
  }
  instr(): LuaInstr {
    const i = this.u32();
    return { pc: 0, opcode: i & 0x3F, a: (i >>> 6) & 0xFF, c: (i >>> 14) & 0x1FF, b: (i >>> 23) & 0x1FF, bx: i >>> 14, sbx: (i >>> 14) - 131071 };
  }
}

function parseHeader(d: Uint8Array): LuaHeader | null {
  if (d.length < 12) return null;
  if (ascii(d,0,4) !== '\x1bLua') return null;
  const version = d[4];
  const jit = version === 0x51 && (d[12] === 0x4a || d[13] === 0x4a); // 'J' marker
  return { version, format: d[5], littleEndian: d[6] === 1, intSize: d[7], sizetSize: d[8], instrSize: d[9], luaNumSize: d[10], integral: d[11] === 1, jit };
}

function parseProto(r: Reader, h: LuaHeader, parentSource: string, depth: number): LuaProto {
  const source = depth === 0 ? r.str() : parentSource;
  const linedefined = r.int();
  const lastlinedefined = r.int();
  const numparams = r.byte();
  const is_vararg = r.byte();
  const maxstacksize = r.byte();
  const sizecode = r.int();
  const code: LuaInstr[] = [];
  for (let i = 0; i < sizecode; i++) code.push(r.instr());
  const sizek = r.int();
  const constants: LuaConst[] = [];
  for (let i = 0; i < sizek; i++) {
    const t = r.byte();
    switch (t) {
      case 0: constants.push({type:'nil',value:null}); break;
      case 1: constants.push({type:'bool',value:r.byte()!==0}); break;
      case 3: constants.push({type:'num',value:r.num()}); break;
      case 4: constants.push({type:'str',value:r.str()}); break;
      case 2: case 5: case 6: case 7: case 8: case 9: case 10: case 11: case 12: case 13: case 14: case 15: case 16: case 17: case 18: case 19: case 20: case 21: case 22: { // LUA_TSHRSTR..LUA_TTHREAD (5.4)
        constants.push({type:'str',value:r.str()}); break;
      }
      default: constants.push({type:'unknown',value:t});
    }
  }
  const sizeup = r.int();
  const upvalues = [];
  for (let i = 0; i < sizeup; i++) {
    const instack = r.byte(); const idx = r.byte(); const kind = h.version >= 0x54 ? r.byte() : 0;
    upvalues.push({ name: `up${i}`, instack, idx });
  }
  const sizep = r.int();
  const protos: LuaProto[] = [];
  for (let i = 0; i < sizep; i++) protos.push(parseProto(r, h, source, depth + 1));
  // debug info
  const sizeline = r.int();
  const lineinfo = [];
  for (let i = 0; i < sizeline; i++) lineinfo.push(r.int());
  const sizeloc = r.int();
  for (let i = 0; i < sizeloc; i++) { r.str(); r.int(); r.int(); }
  const sizeupn = r.int();
  for (let i = 0; i < sizeupn; i++) { const n = r.str(); if (upvalues[i]) upvalues[i].name = n; }
  return { name: source || 'main', linedefined, lastlinedefined, numparams, is_vararg, maxstacksize, code, constants, upvalues, protos, lineinfo };
}

export function isLuaBytecode(d: Uint8Array): boolean {
  return parseHeader(d) !== null;
}

export function decompileLua(d: Uint8Array) {
  const h = parseHeader(d);
  if (!h) throw new Error('Not Lua bytecode (bad signature)');
  const r = new Reader(d, h);
  r.pos = h.version === 0x51 && h.jit ? 14 : 12;
  // skip header tail for 5.3/5.4
  if (h.version >= 0x53) { r.pos = 12 + 6 + 5 + 8; } // skip LUAC_DATA etc — approximate
  const main = parseProto(r, h, '', 0);
  const ops = h.version >= 0x54 ? LUA54_OPS : h.version >= 0x53 ? LUA53_OPS : LUA51_OPS;
  const verStr = h.jit ? 'LuaJIT 2.1' : `Lua 5.${h.version - 0x50}`;

  let totalInstr = 0, funcCount = 0;
  const disasmLines: string[] = [];
  const pseudoLines: string[] = [];

  function walk(p: LuaProto, depth: number) {
    funcCount++; totalInstr += p.code.length;
    const pad = '  '.repeat(depth);
    const fname = depth === 0 ? 'main' : `function_${funcCount}`;
    disasmLines.push(`${pad}-- ${fname} (lines ${p.linedefined}-${p.lastlinedefined}), ${p.numparams} params, ${p.maxstacksize} slots`);
    pseudoLines.push(`${pad}-- ${fname}(${Array.from({length:p.numparams},(_,i)=>'a'+i).join(', ')})`);
    if (depth > 0) pseudoLines.push(`${pad}local function ${fname}(${Array.from({length:p.numparams},(_,i)=>'a'+i).join(', ')})`);

    const k = (i: number) => { const c = p.constants[i]; return c ? (c.type==='str' ? JSON.stringify(c.value) : c.type==='num' ? String(c.value) : String(c.value)) : `k${i}`; };
    const rk = (v: number) => v < 256 ? `r${v}` : k(v - 256);
    const reg = (i: number) => 'r' + i;

    p.code.forEach((ins, pc) => {
      const op = ops[ins.opcode] || `OP_${ins.opcode}`;
      let args = '';
      switch (ins.opcode) {
        case 0: args = `${reg(ins.a)}, ${reg(ins.b)}`; break;
        case 1: case 2: case 5: case 6: case 7: case 8: case 9: case 10: case 11: case 12:
          args = `${reg(ins.a)}, ${k(ins.bx)}`; break;
        case 22: args = `${ins.sbx}`; break; // JMP
        case 23: case 24: case 25: args = `${ins.a}, ${rk(ins.b)}, ${rk(ins.c)}`; break;
        case 26: case 27: args = `${reg(ins.a)}, ${ins.c}`; break;
        case 28: case 30: case 31: args = `${reg(ins.a)}, ${ins.b}, ${ins.c}`; break;
        case 29: args = `${reg(ins.a)}, ${ins.b}`; break;
        case 32: case 33: args = `${ins.sbx}`; break;
        default: args = `${ins.a}, ${ins.b}, ${ins.c}`;
      }
      disasmLines.push(`${pad}  [${pc.toString().padStart(4)}] ${op.padEnd(12)} ${args}`);
      // pseudo
      switch (op) {
        case 'MOVE': pseudoLines.push(`${pad}${reg(ins.a)} = ${reg(ins.b)}`); break;
        case 'LOADK': case 'LOADI': case 'LOADF': pseudoLines.push(`${pad}${reg(ins.a)} = ${k(ins.bx)}`); break;
        case 'LOADBOOL': pseudoLines.push(`${pad}${reg(ins.a)} = ${ins.b !== 0}`); break;
        case 'LOADNIL': pseudoLines.push(`${pad}${reg(ins.a)} = nil`); break;
        case 'GETGLOBAL': case 'GETTABUP': pseudoLines.push(`${pad}${reg(ins.a)} = ${k(ins.bx)}[${k(ins.c)}]`); break;
        case 'GETTABLE': case 'GETFIELD': case 'GETI': pseudoLines.push(`${pad}${reg(ins.a)} = ${rk(ins.b)}[${rk(ins.c)}]`); break;
        case 'SETGLOBAL': case 'SETTABUP': pseudoLines.push(`${pad}${k(ins.bx)} = ${rk(ins.a)}`); break;
        case 'SETTABLE': case 'SETFIELD': case 'SETI': pseudoLines.push(`${pad}${rk(ins.a)}[${rk(ins.b)}] = ${rk(ins.c)}`); break;
        case 'NEWTABLE': pseudoLines.push(`${pad}${reg(ins.a)} = {}`); break;
        case 'SELF': pseudoLines.push(`${pad}${reg(ins.a+1)} = ${rk(ins.b)}; ${reg(ins.a)} = ${rk(ins.b)}[${rk(ins.c)}]`); break;
        case 'ADD': case 'SUB': case 'MUL': case 'DIV': case 'MOD': case 'POW': case 'IDIV':
        case 'BAND': case 'BOR': case 'BXOR': case 'SHL': case 'SHR':
        case 'ADDK': case 'SUBK': case 'MULK': case 'DIVK': case 'MODK': case 'POWK': case 'IDIVK': {
          const sym: any = {ADD:'+',SUB:'-',MUL:'*',DIV:'/',MOD:'%',POW:'^',IDIV:'//',BAND:'&',BOR:'|',BXOR:'~',SHL:'<<',SHR:'>>',ADDK:'+',SUBK:'-',MULK:'*',DIVK:'/',MODK:'%',POWK:'^',IDIVK:'//'};
          pseudoLines.push(`${pad}${reg(ins.a)} = ${rk(ins.b)} ${sym[op]||'?'} ${rk(ins.c)}`); break;
        }
        case 'UNM': pseudoLines.push(`${pad}${reg(ins.a)} = -${rk(ins.b)}`); break;
        case 'BNOT': pseudoLines.push(`${pad}${reg(ins.a)} = ~${rk(ins.b)}`); break;
        case 'NOT': pseudoLines.push(`${pad}${reg(ins.a)} = not ${rk(ins.b)}`); break;
        case 'LEN': pseudoLines.push(`${pad}${reg(ins.a)} = #${rk(ins.b)}`); break;
        case 'CONCAT': pseudoLines.push(`${pad}${reg(ins.a)} = ${rk(ins.b)} .. ${rk(ins.c)}`); break;
        case 'JMP': pseudoLines.push(`${pad}goto ${pc + 1 + ins.sbx}`); break;
        case 'EQ': case 'EQK': case 'EQI': pseudoLines.push(`${pad}if (${rk(ins.b)} == ${rk(ins.c)}) ~= ${ins.a} then goto ${pc+2}`); break;
        case 'LT': case 'LTI': pseudoLines.push(`${pad}if (${rk(ins.b)} < ${rk(ins.c)}) ~= ${ins.a} then goto ${pc+2}`); break;
        case 'LE': case 'LEI': pseudoLines.push(`${pad}if (${rk(ins.b)} <= ${rk(ins.c)}) ~= ${ins.a} then goto ${pc+2}`); break;
        case 'CALL': {
          const args = [];
          for (let i = 1; i <= ins.b - 1; i++) args.push(reg(ins.a + i));
          const rets = [];
          for (let i = 0; i <= ins.c - 2; i++) rets.push(reg(ins.a + i));
          pseudoLines.push(`${pad}${rets.length ? rets.join(', ') + ' = ' : ''}${reg(ins.a)}(${args.join(', ')})`);
          break;
        }
        case 'TAILCALL': pseudoLines.push(`${pad}return ${reg(ins.a)}(${reg(ins.a+1)})`); break;
        case 'RETURN': case 'RETURN0': case 'RETURN1': {
          if (ins.b === 1) { pseudoLines.push(`${pad}return`); break; }
          const rets = [];
          for (let i = 0; i <= ins.b - 2; i++) rets.push(rk(ins.a + i));
          pseudoLines.push(`${pad}return ${rets.join(', ')}`);
          break;
        }
        case 'FORLOOP': pseudoLines.push(`${pad}for ${reg(ins.a)} do ... end`); break;
        case 'FORPREP': pseudoLines.push(`${pad}for ${reg(ins.a)} = ... do`); break;
        case 'CLOSURE': pseudoLines.push(`${pad}${reg(ins.a)} = closure(proto[${ins.bx}])`); break;
        case 'VARARG': pseudoLines.push(`${pad}${reg(ins.a)} = ...`); break;
        case 'SETLIST': pseudoLines.push(`${pad}setlist(${reg(ins.a)}, ${ins.b})`); break;
      }
    });
    p.protos.forEach(c => walk(c, depth + 1));
    if (depth > 0) pseudoLines.push(`${pad}end`);
  }
  walk(main, 0);

  return {
    detected: `${verStr} bytecode${h.jit ? ' (LuaJIT)' : ''}`,
    pseudo: pseudoLines.join('\n'),
    disasm: disasmLines.join('\n'),
    il: disasmLines.join('\n'),
    strings: extractStrings(d),
    hexPreview: hexDump(d),
    stats: { functions: funcCount, instructions: totalInstr, strings: extractStrings(d).length, size: d.length }
  };
}
