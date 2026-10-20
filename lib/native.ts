
import { u8, u16, u32, u64, ascii, cstr, hexDump, extractStrings } from './format';

// ── x86-64 opcode disassembler (subset, common instructions) ──
interface Ins { addr: number; bytes: number[]; mnemonic: string; ops: string; size: number; }

const R64 = ['rax','rcx','rdx','rbx','rsp','rbp','rsi','rdi','r8','r9','r10','r11','r12','r13','r14','r15'];
const R32 = ['eax','ecx','edx','ebx','esp','ebp','esi','edi','r8d','r9d','r10d','r11d','r12d','r13d','r14d','r15d'];
const R16 = ['ax','cx','dx','bx','sp','bp','si','di','r8w','r9w','r10w','r11w','r12w','r13w','r14w','r15w'];
const R8L = ['al','cl','dl','bl','spl','bpl','sil','dil','r8b','r9b','r10b','r11b','r12b','r13b','r14b','r15b'];

function disasm(d: Uint8Array, base: number, len: number): Ins[] {
  const out: Ins[] = [];
  let i = 0;
  while (i < len && out.length < 5000) {
    const start = i;
    const addr = base + i;
    let rex = 0, prefix66 = false, prefixF2 = false, prefixF3 = false;
    // prefixes
    while (i < len) {
      const b = d[i];
      if (b >= 0x40 && b <= 0x4F) { rex = b; i++; }
      else if (b === 0x66) { prefix66 = true; i++; }
      else if (b === 0xF2) { prefixF2 = true; i++; }
      else if (b === 0xF3) { prefixF3 = true; i++; }
      else if (b === 0x2E || b === 0x3E || b === 0x26 || b === 0x36 || b === 0x64 || b === 0x65 || b === 0x67) { i++; }
      else break;
    }
    if (i >= len) break;
    const op = d[i++];
    let mnemonic = '', ops = '';
    const w = (rex & 8) !== 0;
    const regSet = w ? R64 : prefix66 ? R16 : R32;
    const modrm = () => { if (i >= len) return 0; const m = d[i++]; const mod = m >> 6, reg = ((m >> 3) & 7) | ((rex & 4) << 1), rm = (m & 7) | ((rex & 1) << 3); return (mod << 8) | (reg << 4) | rm; };
    const imm8 = () => { const v = d[i++]; return v; };
    const imm32 = () => { const v = u32(d, i); i += 4; return v; };
    const disp32 = () => { const v = u32(d, i) | 0; i += 4; return v; };

    const fmtRM = (mod: number, reg: number, rm: number): string => {
      if (mod === 3) return regSet[rm];
      let base = rm & 7, idx = -1, scale = 1, disp = 0;
      if ((rm & 7) === 4) { const sib = d[i++]; scale = 1 << (sib >> 6); idx = ((sib >> 3) & 7) | ((rex & 2) << 2); base = (sib & 7) | ((rex & 1) << 3); }
      if (mod === 0 && (rm & 7) === 5) { disp = disp32(); base = -1; }
      else if (mod === 1) disp = ((d[i++] << 24) >> 24);
      else if (mod === 2) disp = disp32();
      let s = '[';
      if (base >= 0) s += R64[base];
      if (idx >= 0 && idx !== 4) s += (base >= 0 ? '+' : '') + R64[idx] + (scale > 1 ? '*' + scale : '');
      if (disp !== 0 || base < 0) s += (disp >= 0 && base >= 0 ? '+' : '') + '0x' + (disp >>> 0).toString(16);
      return s + ']';
    };

    switch (op) {
      case 0x55: mnemonic='push'; ops='rbp'; break;
      case 0x53: mnemonic='push'; ops='rbx'; break;
      case 0x56: mnemonic='push'; ops='rsi'; break;
      case 0x57: mnemonic='push'; ops='rdi'; break;
      case 0x5D: mnemonic='pop'; ops='rbp'; break;
      case 0x5B: mnemonic='pop'; ops='rbx'; break;
      case 0x5E: mnemonic='pop'; ops='rsi'; break;
      case 0x5F: mnemonic='pop'; ops='rdi'; break;
      case 0x90: mnemonic='nop'; break;
      case 0xC3: mnemonic='ret'; break;
      case 0xCC: mnemonic='int3'; break;
      case 0xCD: mnemonic='int'; ops=imm8().toString(); break;
      case 0xE8: { const t = disp32(); mnemonic='call'; ops='0x' + (addr + 5 + t).toString(16); break; }
      case 0xE9: { const t = disp32(); mnemonic='jmp'; ops='0x' + (addr + 5 + t).toString(16); break; }
      case 0xEB: { const t = ((d[i++] << 24) >> 24); mnemonic='jmp'; ops='0x' + (addr + 2 + t).toString(16); break; }
      case 0x74: { const t = ((d[i++] << 24) >> 24); mnemonic='jz'; ops='0x' + (addr + 2 + t).toString(16); break; }
      case 0x75: { const t = ((d[i++] << 24) >> 24); mnemonic='jnz'; ops='0x' + (addr + 2 + t).toString(16); break; }
      case 0x7E: { const t = ((d[i++] << 24) >> 24); mnemonic='jle'; ops='0x' + (addr + 2 + t).toString(16); break; }
      case 0x7F: { const t = ((d[i++] << 24) >> 24); mnemonic='jg'; ops='0x' + (addr + 2 + t).toString(16); break; }
      case 0x7C: { const t = ((d[i++] << 24) >> 24); mnemonic='jl'; ops='0x' + (addr + 2 + t).toString(16); break; }
      case 0x7D: { const t = ((d[i++] << 24) >> 24); mnemonic='jge'; ops='0x' + (addr + 2 + t).toString(16); break; }
      case 0x72: { const t = ((d[i++] << 24) >> 24); mnemonic='jb'; ops='0x' + (addr + 2 + t).toString(16); break; }
      case 0x73: { const t = ((d[i++] << 24) >> 24); mnemonic='jae'; ops='0x' + (addr + 2 + t).toString(16); break; }
      case 0x76: { const t = ((d[i++] << 24) >> 24); mnemonic='jbe'; ops='0x' + (addr + 2 + t).toString(16); break; }
      case 0x77: { const t = ((d[i++] << 24) >> 24); mnemonic='ja'; ops='0x' + (addr + 2 + t).toString(16); break; }
      case 0x0F: {
        const op2 = d[i++];
        if (op2 >= 0x80 && op2 <= 0x8F) { const t = disp32(); const cc = ['jo','jno','jb','jae','jz','jnz','jbe','ja','js','jns','jp','jnp','jl','jge','jle','jg'][op2-0x80]; mnemonic=cc; ops='0x'+(addr+6+t).toString(16); }
        else if (op2 === 0xAF) { const m = modrm(); mnemonic='imul'; ops=`${regSet[(m>>4)&15]}, ${fmtRM(m>>8,(m>>4)&15,m&15)}`; }
        else if (op2 === 0xB6 || op2 === 0xB7) { const m = modrm(); mnemonic='movzx'; ops=`${regSet[(m>>4)&15]}, ${fmtRM(m>>8,(m>>4)&15,m&15)}`; }
        else if (op2 === 0xBE || op2 === 0xBF) { const m = modrm(); mnemonic='movsx'; ops=`${regSet[(m>>4)&15]}, ${fmtRM(m>>8,(m>>4)&15,m&15)}`; }
        else if (op2 === 0x1F) { const m = modrm(); mnemonic='nop'; ops=fmtRM(m>>8,(m>>4)&15,m&15); }
        else { mnemonic=`0f_${op2.toString(16)}`; }
        break;
      }
      case 0x89: { const m = modrm(); mnemonic='mov'; ops=`${fmtRM(m>>8,(m>>4)&15,m&15)}, ${regSet[(m>>4)&15]}`; break; }
      case 0x8B: { const m = modrm(); mnemonic='mov'; ops=`${regSet[(m>>4)&15]}, ${fmtRM(m>>8,(m>>4)&15,m&15)}`; break; }
      case 0x88: { const m = modrm(); mnemonic='mov'; ops=`${fmtRM(m>>8,(m>>4)&15,m&15)}, ${R8L[(m>>4)&15]}`; break; }
      case 0x8A: { const m = modrm(); mnemonic='mov'; ops=`${R8L[(m>>4)&15]}, ${fmtRM(m>>8,(m>>4)&15,m&15)}`; break; }
      case 0x8D: { const m = modrm(); mnemonic='lea'; ops=`${regSet[(m>>4)&15]}, ${fmtRM(m>>8,(m>>4)&15,m&15)}`; break; }
      case 0xC7: { const m = modrm(); mnemonic='mov'; ops=`${fmtRM(m>>8,(m>>4)&15,m&15)}, 0x${imm32().toString(16)}`; break; }
      case 0xC6: { const m = modrm(); mnemonic='mov'; ops=`${fmtRM(m>>8,(m>>4)&15,m&15)}, 0x${imm8().toString(16)}`; break; }
      case 0xB8: case 0xB9: case 0xBA: case 0xBB: case 0xBC: case 0xBD: case 0xBE: case 0xBF: {
        const r = (op - 0xB8) | ((rex & 1) << 3);
        if (w) { const v = u64(d, i); i += 8; mnemonic='mov'; ops=`${R64[r]}, 0x${v.toString(16)}`; }
        else { const v = imm32(); mnemonic='mov'; ops=`${R32[r]}, 0x${v.toString(16)}`; }
        break;
      }
      case 0x31: { const m = modrm(); mnemonic='xor'; ops=`${fmtRM(m>>8,(m>>4)&15,m&15)}, ${regSet[(m>>4)&15]}`; break; }
      case 0x33: { const m = modrm(); mnemonic='xor'; ops=`${regSet[(m>>4)&15]}, ${fmtRM(m>>8,(m>>4)&15,m&15)}`; break; }
      case 0x01: { const m = modrm(); mnemonic='add'; ops=`${fmtRM(m>>8,(m>>4)&15,m&15)}, ${regSet[(m>>4)&15]}`; break; }
      case 0x03: { const m = modrm(); mnemonic='add'; ops=`${regSet[(m>>4)&15]}, ${fmtRM(m>>8,(m>>4)&15,m&15)}`; break; }
      case 0x29: { const m = modrm(); mnemonic='sub'; ops=`${fmtRM(m>>8,(m>>4)&15,m&15)}, ${regSet[(m>>4)&15]}`; break; }
      case 0x2B: { const m = modrm(); mnemonic='sub'; ops=`${regSet[(m>>4)&15]}, ${fmtRM(m>>8,(m>>4)&15,m&15)}`; break; }
      case 0x39: { const m = modrm(); mnemonic='cmp'; ops=`${fmtRM(m>>8,(m>>4)&15,m&15)}, ${regSet[(m>>4)&15]}`; break; }
      case 0x3B: { const m = modrm(); mnemonic='cmp'; ops=`${regSet[(m>>4)&15]}, ${fmtRM(m>>8,(m>>4)&15,m&15)}`; break; }
      case 0x83: { const m = modrm(); const sub = (m >> 4) & 7; const t = ((d[i++] << 24) >> 24); const names = ['add','or','adc','sbb','and','sub','xor','cmp']; mnemonic=names[sub]; ops=`${fmtRM(m>>8,(m>>4)&15,m&15)}, ${t}`; break; }
      case 0x81: { const m = modrm(); const sub = (m >> 4) & 7; const t = imm32(); const names = ['add','or','adc','sbb','and','sub','xor','cmp']; mnemonic=names[sub]; ops=`${fmtRM(m>>8,(m>>4)&15,m&15)}, 0x${t.toString(16)}`; break; }
      case 0x80: { const m = modrm(); const sub = (m >> 4) & 7; const t = imm8(); const names = ['add','or','adc','sbb','and','sub','xor','cmp']; mnemonic=names[sub]; ops=`${R8L[m&15]}, ${t}`; break; }
      case 0xFF: { const m = modrm(); const sub = (m >> 4) & 7; const rm = fmtRM(m>>8,(m>>4)&15,m&15); if (sub===0) {mnemonic='inc';ops=rm;} else if (sub===1) {mnemonic='dec';ops=rm;} else if (sub===2) {mnemonic='call';ops=rm;} else if (sub===4) {mnemonic='jmp';ops=rm;} else if (sub===6) {mnemonic='push';ops=rm;} else {mnemonic=`ff_${sub}`;ops=rm;} break; }
      case 0xF7: { const m = modrm(); const sub = (m >> 4) & 7; const rm = fmtRM(m>>8,(m>>4)&15,m&15); if (sub===0) {mnemonic='test';ops=`${rm}, 0x${imm32().toString(16)}`;} else if (sub===2) {mnemonic='not';ops=rm;} else if (sub===3) {mnemonic='neg';ops=rm;} else if (sub===4) {mnemonic='mul';ops=rm;} else if (sub===5) {mnemonic='imul';ops=rm;} else if (sub===6) {mnemonic='div';ops=rm;} else {mnemonic='idiv';ops=rm;} break; }
      case 0xF6: { const m = modrm(); const sub = (m >> 4) & 7; const rm = fmtRM(m>>8,(m>>4)&15,m&15); if (sub===0) {mnemonic='test';ops=`${rm}, 0x${imm8().toString(16)}`;} else mnemonic=`f6_${sub}`; break; }
      case 0x85: { const m = modrm(); mnemonic='test'; ops=`${fmtRM(m>>8,(m>>4)&15,m&15)}, ${regSet[(m>>4)&15]}`; break; }
      case 0x50: case 0x51: case 0x52: case 0x53: case 0x54: case 0x55: case 0x56: case 0x57: mnemonic='push'; ops=regSet[(op-0x50)|((rex&1)<<3)]; break;
      case 0x58: case 0x59: case 0x5A: case 0x5B: case 0x5C: case 0x5D: case 0x5E: case 0x5F: mnemonic='pop'; ops=regSet[(op-0x58)|((rex&1)<<3)]; break;
      case 0x68: mnemonic='push'; ops='0x'+imm32().toString(16); break;
      case 0x6A: mnemonic='push'; ops=((d[i++]<<24)>>24).toString(); break;
      case 0xA1: { const v = w ? u64(d,i) : imm32(); mnemonic='mov'; ops=`${w?'rax':'eax'}, [0x${v.toString(16)}]`; if (w) i+=4; break; }
      case 0xA3: { const v = w ? u64(d,i) : imm32(); mnemonic='mov'; ops=`[0x${v.toString(16)}], ${w?'rax':'eax'}`; if (w) i+=4; break; }
      case 0xD1: case 0xD3: case 0xC1: { const m = modrm(); const sub=(m>>4)&7; const rm=fmtRM(m>>8,(m>>4)&15,m&15); const cnt = op===0xD1?'1':op===0xD3?'cl':imm8().toString(); mnemonic=['rol','ror','rcl','rcr','shl','shr','sal','sar'][sub]; ops=`${rm}, ${cnt}`; break; }
      case 0xF3: mnemonic='rep'; break;
      case 0xA4: mnemonic='movsb'; break;
      case 0xA5: mnemonic='movsd'; break;
      case 0xAA: mnemonic='stosb'; break;
      case 0xAB: mnemonic='stosd'; break;
      case 0xAE: mnemonic='scasb'; break;
      case 0xC9: mnemonic='leave'; break;
      case 0x98: mnemonic='cwde'; break;
      case 0x99: mnemonic='cdq'; break;
      case 0xF8: mnemonic='clc'; break;
      case 0xF9: mnemonic='stc'; break;
      case 0xFC: mnemonic='cld'; break;
      case 0xFD: mnemonic='std'; break;
      case 0xFA: mnemonic='cli'; break;
      case 0xFB: mnemonic='sti'; break;
      case 0x04: mnemonic='add'; ops=`al, ${imm8()}`; break;
      case 0x0C: mnemonic='or'; ops=`al, ${imm8()}`; break;
      case 0x24: mnemonic='and'; ops=`al, ${imm8()}`; break;
      case 0x34: mnemonic='xor'; ops=`al, ${imm8()}`; break;
      case 0x3C: mnemonic='cmp'; ops=`al, ${imm8()}`; break;
      case 0xEC: mnemonic='in'; ops='al, dx'; break;
      case 0xEE: mnemonic='out'; ops='dx, al'; break;
      default: mnemonic=`db 0x${op.toString(16)}`;
    }
    const bytes = Array.from(d.slice(start, i));
    out.push({ addr, bytes, mnemonic, ops, size: i - start });
  }
  return out;
}

// ── PE parser ──
export function isPE(d: Uint8Array): boolean {
  return d.length > 0x40 && d[0] === 0x4D && d[1] === 0x5A && ascii(d, u32(d,0x3C), 4) === 'PE\x00\x00';
}

export function parsePE(d: Uint8Array) {
  const peOff = u32(d, 0x3C);
  const numSections = u16(d, peOff + 6);
  const optSize = u16(d, peOff + 20);
  const optOff = peOff + 24;
  const imageBase = u64(d, optOff + 24);
  const entryRva = u32(d, optOff + 16);
  const sections = [];
  let off = optOff + optSize;
  for (let i = 0; i < numSections; i++) {
    sections.push({ name: ascii(d, off, 8).replace(/\0.*$/,''), vsize: u32(d, off+8), vaddr: u32(d, off+12), rawsize: u32(d, off+16), rawptr: u32(d, off+20) });
    off += 40;
  }
  const rvaToOff = (rva: number) => {
    for (const s of sections) if (rva >= s.vaddr && rva < s.vaddr + Math.max(s.vsize, s.rawsize)) return s.rawptr + (rva - s.vaddr);
    return -1;
  };
  const entryOff = rvaToOff(entryRva);
  const dis = disasm(d, entryOff >= 0 ? entryOff : 0, Math.min(4096, d.length - (entryOff >= 0 ? entryOff : 0)));
  const strings = extractStrings(d);
  const disLines = dis.map(i => `  ${i.addr.toString(16).padStart(8,'0')}  ${i.bytes.map(b=>b.toString(16).padStart(2,'0')).join(' ').padEnd(20)}  ${i.mnemonic} ${i.ops}`);
  const pseudo: string[] = [
    `// PE32+ executable, entry RVA 0x${entryRva.toString(16)}, image base 0x${imageBase.toString(16)}`,
    `// Sections: ${sections.map(s=>s.name).join(', ')}`,
    '',
    'int entry() {'
  ];
  dis.forEach(i => {
    switch (i.mnemonic) {
      case 'call': pseudo.push(`  func_${i.ops.replace('0x','')}();`); break;
      case 'mov': pseudo.push(`  ${i.ops.replace(',', ' =')};`); break;
      case 'push': pseudo.push(`  push(${i.ops});`); break;
      case 'pop': pseudo.push(`  ${i.ops} = pop();`); break;
      case 'ret': pseudo.push('  return;'); break;
      case 'jmp': pseudo.push(`  goto ${i.ops};`); break;
      case 'jz': pseudo.push(`  if (zero) goto ${i.ops};`); break;
      case 'jnz': pseudo.push(`  if (!zero) goto ${i.ops};`); break;
      case 'cmp': pseudo.push(`  cmp(${i.ops});`); break;
      case 'test': pseudo.push(`  test(${i.ops});`); break;
      case 'xor': pseudo.push(`  ${i.ops.replace(',', ' ^=')};`); break;
      case 'add': pseudo.push(`  ${i.ops.replace(',', ' +=')};`); break;
      case 'sub': pseudo.push(`  ${i.ops.replace(',', ' -=')};`); break;
      case 'nop': break;
      default: pseudo.push(`  __asm("${i.mnemonic} ${i.ops}");`);
    }
  });
  pseudo.push('}');
  return {
    detected: 'PE32+ (Windows x86-64)',
    pseudo: pseudo.join('\n'),
    disasm: disLines.join('\n'),
    strings,
    hexPreview: hexDump(d),
    stats: { functions: dis.filter(i=>i.mnemonic==='call').length, instructions: dis.length, strings: strings.length, size: d.length }
  };
}

// ── ELF parser ──
export function isELF(d: Uint8Array): boolean {
  return d.length > 16 && d[0] === 0x7F && d[1] === 0x45 && d[2] === 0x4C && d[3] === 0x46;
}

export function parseELF(d: Uint8Array) {
  const is64 = d[4] === 2;
  const entry = is64 ? Number(u64(d, 24)) : u32(d, 24);
  const phoff = is64 ? Number(u64(d, 32)) : u32(d, 28);
  const shoff = is64 ? Number(u64(d, 40)) : u32(d, 32);
  const phentsize = u16(d, is64 ? 54 : 42);
  const phnum = u16(d, is64 ? 56 : 44);
  const shentsize = u16(d, is64 ? 58 : 46);
  const shnum = u16(d, is64 ? 60 : 48);
  const shstrndx = u16(d, is64 ? 62 : 50);

  const sections: { name: string; type: number; addr: number; offset: number; size: number }[] = [];
  for (let i = 0; i < shnum; i++) {
    const o = shoff + i * shentsize;
    sections.push({ name: '', type: u32(d, o+4), addr: is64 ? Number(u64(d, o+16)) : u32(d, o+12), offset: is64 ? Number(u64(d, o+24)) : u32(d, o+16), size: is64 ? Number(u64(d, o+32)) : u32(d, o+20) });
  }
  if (shstrndx < shnum) {
    const stroff = sections[shstrndx].offset;
    sections.forEach((s, i) => {
      const o = shoff + i * shentsize;
      s.name = cstr(d, stroff + u32(d, o));
    });
  }
  const text = sections.find(s => s.name === '.text') || sections[1];
  const dis = disasm(d, text ? text.offset : 0, Math.min(4096, text ? text.size : d.length));
  const strings = extractStrings(d);
  const disLines = dis.map(i => `  ${i.addr.toString(16).padStart(8,'0')}  ${i.bytes.map(b=>b.toString(16).padStart(2,'0')).join(' ').padEnd(20)}  ${i.mnemonic} ${i.ops}`);
  const pseudo: string[] = [
    `// ELF${is64 ? '64' : '32'}, entry 0x${entry.toString(16)}, ${sections.length} sections`,
    `// Sections: ${sections.map(s=>s.name).filter(Boolean).join(', ')}`,
    '',
    'int entry() {'
  ];
  dis.forEach(i => {
    switch (i.mnemonic) {
      case 'call': pseudo.push(`  func_${i.ops.replace('0x','')}();`); break;
      case 'mov': pseudo.push(`  ${i.ops.replace(',', ' =')};`); break;
      case 'ret': pseudo.push('  return;'); break;
      case 'jmp': pseudo.push(`  goto ${i.ops};`); break;
      case 'jz': pseudo.push(`  if (zero) goto ${i.ops};`); break;
      case 'jnz': pseudo.push(`  if (!zero) goto ${i.ops};`); break;
      case 'cmp': pseudo.push(`  cmp(${i.ops});`); break;
      case 'push': pseudo.push(`  push(${i.ops});`); break;
      case 'pop': pseudo.push(`  ${i.ops} = pop();`); break;
      default: pseudo.push(`  __asm("${i.mnemonic} ${i.ops}");`);
    }
  });
  pseudo.push('}');
  return {
    detected: `ELF${is64 ? '64' : '32'} (Linux x86-64)`,
    pseudo: pseudo.join('\n'),
    disasm: disLines.join('\n'),
    strings,
    hexPreview: hexDump(d),
    stats: { functions: dis.filter(i=>i.mnemonic==='call').length, instructions: dis.length, strings: strings.length, size: d.length }
  };
}
