
import { u16, u32, u64, ascii, cstr, hexDump, extractStrings } from './format';

interface PEInfo { rva: number; sections: { name: string; vsize: number; vaddr: number; rawsize: number; rawptr: number }[]; cliRva: number; cliSize: number; metadataRva: number; entryToken: number; }

function rvaToOff(rva: number, s: PEInfo['sections']): number {
  for (const sec of s) {
    if (rva >= sec.vaddr && rva < sec.vaddr + Math.max(sec.vsize, sec.rawsize))
      return sec.rawptr + (rva - sec.vaddr);
  }
  return -1;
}

export function isDotNet(d: Uint8Array): boolean {
  if (d.length < 0x40 || d[0] !== 0x4D || d[1] !== 0x5A) return false; // MZ
  const peOff = u32(d, 0x3C);
  if (ascii(d, peOff, 4) !== 'PE\x00\x00') return false;
  const numSections = u16(d, peOff + 6);
  const optSize = u16(d, peOff + 20);
  const optOff = peOff + 24;
  const magic = u16(d, optOff);
  const ddOff = optOff + (magic === 0x20B ? 112 : 96);
  const cliRva = u32(d, ddOff + 14 * 8);
  const numSecOff = optOff + (magic === 0x20B ? 108 : 92);
  // section headers
  let off = optOff + optSize;
  const sections = [];
  for (let i = 0; i < numSections; i++) {
    sections.push({ name: ascii(d, off, 8).replace(/\0.*$/,''), vsize: u32(d, off+8), vaddr: u32(d, off+12), rawsize: u32(d, off+16), rawptr: u32(d, off+20) });
    off += 40;
  }
  return cliRva !== 0 && rvaToOff(cliRva, sections) >= 0;
}

export function decompileDotNet(d: Uint8Array) {
  const peOff = u32(d, 0x3C);
  const numSections = u16(d, peOff + 6);
  const optSize = u16(d, peOff + 20);
  const optOff = peOff + 24;
  const magic = u16(d, optOff);
  const ddOff = optOff + (magic === 0x20B ? 112 : 96);
  const cliRva = u32(d, ddOff + 14 * 8);
  let off = optOff + optSize;
  const sections = [];
  for (let i = 0; i < numSections; i++) {
    sections.push({ name: ascii(d, off, 8).replace(/\0.*$/,''), vsize: u32(d, off+8), vaddr: u32(d, off+12), rawsize: u32(d, off+16), rawptr: u32(d, off+20) });
    off += 40;
  }
  const cliOff = rvaToOff(cliRva, sections);
  const metadataRva = u32(d, cliOff + 8);
  const metaOff = rvaToOff(metadataRva, sections);

  // ── metadata root ──
  if (ascii(d, metaOff, 4) !== 'BSJB') throw new Error('Bad metadata signature');
  let p = metaOff + 16; // skip sig+ver+reserved
  p += u32(d, p); p += 4; // version string + length field
  p += 2; // flags
  const nStreams = u16(d, p); p += 2;
  const streams: Record<string, { rva: number; size: number }> = {};
  for (let i = 0; i < nStreams; i++) {
    const rva = u32(d, p); const size = u32(d, p+4); p += 8;
    let name = '';
    while (d[p] !== 0) name += String.fromCharCode(d[p++]);
    p += 4 - (name.length % 4); // align 4
    streams[name] = { rva, size };
  }
  const tbl = streams['#~'] || streams['#-'];
  const tblOff = rvaToOff(metadataRva + tbl.rva, sections);
  const strOff = rvaToOff(metadataRva + streams['#Strings'].rva, sections);
  const blobOff = rvaToOff(metadataRva + streams['#Blob'].rva, sections);

  const getStr = (i: number) => i === 0 ? '' : cstr(d, strOff + i);
  const getBlob = (i: number) => {
    if (i === 0) return new Uint8Array(0);
    let q = blobOff + i;
    let len = 0, shift = 0;
    do { const b = d[q++]; len |= (b & 0x7F) << shift; shift += 7; } while (d[q-1] & 0x80);
    return d.slice(q, q + len);
  };

  // ── tables stream ──
  p = tblOff;
  const reserved = u32(d, p); p += 4;
  const major = d[p++], minor = d[p++];
  const heapSizes = d[p++]; p += 1;
  const valid = u64(d, p); p += 8;
  const sorted = u64(d, p); p += 8;
  const rows: number[] = [];
  for (let t = 0; t < 64; t++) if (valid & (1n << BigInt(t))) rows[t] = u32(d, p), p += 4; else rows[t] = 0;

  const strIdxSize = (heapSizes & 1) ? 4 : 2;
  const guidIdxSize = (heapSizes & 2) ? 4 : 2;
  const blobIdxSize = (heapSizes & 4) ? 4 : 2;

  // coded index sizes
  const simple = (t: number) => rows[t] >= 65536 ? 4 : 2;
  const TypeDefOrRef = () => (rows[2] >= 16384 || rows[1] >= 16384 || rows[27] >= 16384) ? 4 : 2;
  const HasConstant = () => (rows[4] >= 16384 || rows[8] >= 16384 || rows[23] >= 16384) ? 4 : 2;
  const HasCustomAttribute = () => (rows[6]>=128||rows[4]>=128||rows[1]>=128||rows[2]>=128||rows[8]>=128||rows[9]>=128||rows[10]>=128||rows[0]>=128||rows[14]>=128||rows[23]>=128||rows[20]>=128||rows[17]>=128||rows[26]>=128||rows[27]>=128||rows[32]>=128||rows[35]>=128||rows[38]>=128||rows[39]>=128||rows[40]>=128||rows[42]>=128||rows[44]>=128||rows[43]>=128) ? 4 : 2;
  const HasFieldMarshal = () => (rows[4] >= 16384 || rows[8] >= 16384) ? 4 : 2;
  const HasDeclSecurity = () => (rows[2] >= 8192 || rows[6] >= 8192 || rows[32] >= 8192) ? 4 : 2;
  const MemberRefParent = () => (rows[2]>=4096||rows[1]>=4096||rows[26]>=4096||rows[6]>=4096||rows[27]>=4096) ? 4 : 2;
  const HasSemantics = () => (rows[20] >= 32768 || rows[23] >= 32768) ? 4 : 2;
  const MethodDefOrRef = () => (rows[6] >= 32768 || rows[10] >= 32768) ? 4 : 2;
  const MemberForwarded = () => (rows[4] >= 32768 || rows[6] >= 32768) ? 4 : 2;
  const Implementation = () => (rows[38]>=8192||rows[35]>=8192||rows[39]>=8192) ? 4 : 2;
  const CustomAttributeType = () => 2; // 3-bit tag, always 2 bytes effectively
  const ResolutionScope = () => (rows[0]>=16384||rows[26]>=16384||rows[35]>=16384||rows[1]>=16384) ? 4 : 2;

  // row size calculators
  const rowSize: Record<number, number> = {
    0: 2 + strIdxSize + strIdxSize, // Module
    1: ResolutionScope() + strIdxSize + strIdxSize, // TypeRef
    2: 4 + strIdxSize + strIdxSize + TypeDefOrRef() + simple(4) + simple(6), // TypeDef
    4: 2 + strIdxSize + blobIdxSize, // Field
    6: 4 + 2 + 2 + strIdxSize + blobIdxSize + simple(8), // MethodDef
    8: 2 + 2 + strIdxSize, // Param
    9: simple(2) + TypeDefOrRef(), // InterfaceImpl
    10: MemberRefParent() + strIdxSize + blobIdxSize, // MemberRef
    11: 2 + HasConstant() + blobIdxSize, // Constant
    12: HasCustomAttribute() + CustomAttributeType() + blobIdxSize, // CustomAttribute
    13: HasFieldMarshal() + blobIdxSize, // FieldMarshal
    14: 2 + HasDeclSecurity() + blobIdxSize, // DeclSecurity
    15: 4 + 4 + simple(2), // ClassLayout
    16: 4 + simple(4), // FieldLayout
    17: blobIdxSize, // StandAloneSig
    18: simple(2) + simple(20), // EventMap
    20: 2 + strIdxSize + TypeDefOrRef(), // Event
    21: simple(2) + simple(23), // PropertyMap
    23: 2 + strIdxSize + blobIdxSize, // Property
    24: 2 + simple(20) + HasSemantics(), // MethodSemantics
    25: simple(2) + simple(20) + simple(20), // MethodImpl
    26: strIdxSize + strIdxSize + strIdxSize, // ModuleRef
    27: 1 + 1 + strIdxSize + blobIdxSize, // TypeSpec
    28: 2 + 2 + simple(6), // ImplMap
    29: 4 + simple(4), // FieldRVA
    30: 8 + 4 + simple(2) + strIdxSize + strIdxSize + Implementation(), // Assembly
    31: 4 + 4 + 4 + 4 + 4 + blobIdxSize + strIdxSize + strIdxSize, // AssemblyProcessor... (approx)
    32: 4 + 2 + 2 + 2 + 2 + 4 + blobIdxSize + strIdxSize + strIdxSize, // AssemblyRef
    33: 4 + 4 + simple(32), // AssemblyRefProcessor
    34: 4 + 4 + simple(32), // AssemblyRefOS
    35: 4 + 2 + 2 + 2 + 2 + 4 + blobIdxSize + strIdxSize + strIdxSize + blobIdxSize, // Assembly (full)
    36: 4 + 4 + simple(35), // AssemblyProcessor
    37: 4 + 4 + simple(35), // AssemblyOS
    38: 4 + strIdxSize + strIdxSize + Implementation(), // File
    39: 4 + strIdxSize + simple(38), // ExportedType
    40: 4 + 4 + strIdxSize + strIdxSize + Implementation(), // ManifestResource
    41: 2 + 2 + simple(2) + strIdxSize, // NestedClass
    42: 2 + 2 + simple(6) + strIdxSize, // GenericParam
    43: 2 + 2 + simple(42) + TypeDefOrRef(), // MethodSpec
    44: 2 + 2 + simple(42) + simple(2), // GenericParamConstraint
  };

  // table row offsets
  const tableOff: Record<number, number> = {};
  let cur = p;
  for (let t = 0; t < 64; t++) {
    if (rows[t]) { tableOff[t] = cur; cur += rows[t] * (rowSize[t] || 0); }
  }

  // ── read tables ──
  interface MethodDef { rva: number; name: string; sig: Uint8Array; paramList: number; }
  interface TypeDef { name: string; ns: string; fieldList: number; methodList: number; }
  const methods: MethodDef[] = [];
  const types: TypeDef[] = [];
  const fields: { name: string; sig: Uint8Array }[] = [];
  const memberRefs: { cls: number; name: string; sig: Uint8Array }[] = [];

  if (rows[6]) {
    let q = tableOff[6];
    for (let i = 0; i < rows[6]; i++) {
      const rva = u32(d, q); q += 4;
      q += 4; // implflags + flags
      const name = getStr(u16(d, q) | (u32(d,q)>>>0 && strIdxSize===4 ? u32(d,q) : 0)); q += strIdxSize;
      const sig = getBlob(strIdxSize === 2 ? u16(d, q) : u32(d, q)); q += blobIdxSize;
      const paramList = strIdxSize === 2 ? u16(d, q) : u32(d, q); q += simple(8);
      methods.push({ rva, name, sig, paramList });
    }
  }
  if (rows[2]) {
    let q = tableOff[2];
    for (let i = 0; i < rows[2]; i++) {
      q += 4;
      const name = getStr(strIdxSize === 2 ? u16(d, q) : u32(d, q)); q += strIdxSize;
      const ns = getStr(strIdxSize === 2 ? u16(d, q) : u32(d, q)); q += strIdxSize;
      q += TypeDefOrRef();
      const fieldList = simple(4) === 2 ? u16(d, q) : u32(d, q); q += simple(4);
      const methodList = simple(6) === 2 ? u16(d, q) : u32(d, q); q += simple(6);
      types.push({ name, ns, fieldList, methodList });
    }
  }
  if (rows[4]) {
    let q = tableOff[4];
    for (let i = 0; i < rows[4]; i++) {
      q += 2;
      const name = getStr(strIdxSize === 2 ? u16(d, q) : u32(d, q)); q += strIdxSize;
      const sig = getBlob(blobIdxSize === 2 ? u16(d, q) : u32(d, q)); q += blobIdxSize;
      fields.push({ name, sig });
    }
  }
  if (rows[10]) {
    let q = tableOff[10];
    for (let i = 0; i < rows[10]; i++) {
      const cls = MemberRefParent() === 2 ? u16(d, q) : u32(d, q); q += MemberRefParent();
      const name = getStr(strIdxSize === 2 ? u16(d, q) : u32(d, q)); q += strIdxSize;
      const sig = getBlob(blobIdxSize === 2 ? u16(d, q) : u32(d, q)); q += blobIdxSize;
      memberRefs.push({ cls, name, sig });
    }
  }

  // ── IL opcodes ──
  const IL: Record<number, [string, number]> = { 0x00:['nop',0],0x01:['break',0],0x02:['ldarg.0',0],0x03:['ldarg.1',0],0x04:['ldarg.2',0],0x05:['ldarg.3',0],0x06:['ldloc.0',0],0x07:['ldloc.1',0],0x08:['ldloc.2',0],0x09:['ldloc.3',0],0x0A:['stloc.0',0],0x0B:['stloc.1',0],0x0C:['stloc.2',0],0x0D:['stloc.3',0],0x0E:['ldarg.s',1],0x0F:['ldarga.s',1],0x10:['starg.s',1],0x11:['ldloc.s',1],0x12:['ldloca.s',1],0x13:['stloc.s',1],0x14:['ldnull',0],0x15:['ldc.i4.m1',0],0x16:['ldc.i4.0',0],0x17:['ldc.i4.1',0],0x18:['ldc.i4.2',0],0x19:['ldc.i4.3',0],0x1A:['ldc.i4.4',0],0x1B:['ldc.i4.5',0],0x1C:['ldc.i4.6',0],0x1D:['ldc.i4.7',0],0x1E:['ldc.i4.8',0],0x1F:['ldc.i4.s',1],0x20:['ldc.i4',4],0x21:['ldc.i8',8],0x22:['ldc.r4',4],0x23:['ldc.r8',8],0x25:['dup',0],0x26:['pop',0],0x27:['jmp',4],0x28:['call',4],0x29:['calli',4],0x2A:['ret',0],0x2B:['br.s',1],0x2C:['brfalse.s',1],0x2D:['brtrue.s',1],0x2E:['beq.s',1],0x2F:['bge.s',1],0x30:['bgt.s',1],0x31:['ble.s',1],0x32:['blt.s',1],0x33:['br',4],0x34:['brfalse',4],0x35:['brtrue',4],0x36:['beq',4],0x37:['bge',4],0x38:['bgt',4],0x39:['ble',4],0x3A:['blt',4],0x3B:['switch',-1],0x3C:['ldind.i1',0],0x3D:['ldind.u1',0],0x3E:['ldind.i2',0],0x3F:['ldind.u2',0],0x40:['ldind.i4',0],0x41:['ldind.u4',0],0x42:['ldind.i8',0],0x43:['ldind.i',0],0x44:['ldind.r4',0],0x45:['ldind.r8',0],0x46:['ldind.ref',0],0x47:['stind.ref',0],0x48:['stind.i1',0],0x49:['stind.i2',0],0x4A:['stind.i4',0],0x4B:['stind.i8',0],0x4C:['stind.r4',0],0x4D:['stind.r8',0],0x4E:['add',0],0x4F:['sub',0],0x50:['mul',0],0x51:['div',0],0x52:['div.un',0],0x53:['rem',0],0x54:['rem.un',0],0x55:['and',0],0x56:['or',0],0x57:['xor',0],0x58:['shl',0],0x59:['shr',0],0x5A:['shr.un',0],0x5B:['neg',0],0x5C:['not',0],0x5D:['conv.i1',0],0x5E:['conv.i2',0],0x5F:['conv.i4',0],0x60:['conv.i8',0],0x61:['conv.r4',0],0x62:['conv.r8',0],0x63:['conv.u4',0],0x64:['conv.u8',0],0x65:['callvirt',4],0x66:['cpobj',4],0x67:['ldobj',4],0x68:['ldstr',4],0x69:['newobj',4],0x6A:['castclass',4],0x6B:['isinst',4],0x6C:['conv.r.un',0],0x6D:['unbox',4],0x6E:['throw',0],0x6F:['ldfld',4],0x70:['ldflda',4],0x71:['stfld',4],0x72:['ldsfld',4],0x73:['ldsflda',4],0x74:['stsfld',4],0x75:['stobj',4],0x76:['conv.ovf.i1.un',0],0x77:['conv.ovf.i2.un',0],0x78:['conv.ovf.i4.un',0],0x79:['conv.ovf.i8.un',0],0x7A:['conv.ovf.u1.un',0],0x7B:['conv.ovf.u2.un',0],0x7C:['conv.ovf.u4.un',0],0x7D:['conv.ovf.u8.un',0],0x7E:['box',4],0x7F:['newarr',4],0x80:['ldlen',0],0x81:['ldelema',4],0x82:['ldelem.i1',0],0x83:['ldelem.u1',0],0x84:['ldelem.i2',0],0x85:['ldelem.u2',0],0x86:['ldelem.i4',0],0x87:['ldelem.u4',0],0x88:['ldelem.i8',0],0x89:['ldelem.i',0],0x8A:['ldelem.r4',0],0x8B:['ldelem.r8',0],0x8C:['ldelem.ref',0],0x8D:['stelem.i',0],0x8E:['stelem.i1',0],0x8F:['stelem.i2',0],0x90:['stelem.i4',0],0x91:['stelem.i8',0],0x92:['stelem.r4',0],0x93:['stelem.r8',0],0x94:['stelem.ref',0],0x95:['ldelem',4],0x96:['stelem',4],0x97:['unbox.any',4],0x98:['conv.ovf.i',0],0x99:['conv.ovf.u',0],0x9A:['conv.ovf.i8',0],0x9B:['conv.ovf.u8',0],0x9C:['refanyval',4],0x9D:['ckfinite',0],0x9E:['mkrefany',4],0x9F:['ldtoken',4],0xA0:['conv.u2',0],0xA1:['conv.u1',0],0xA2:['conv.i',0],0xA3:['conv.ovf.i',0],0xA4:['conv.ovf.u',0],0xA5:['add.ovf',0],0xA6:['add.ovf.un',0],0xA7:['mul.ovf',0],0xA8:['mul.ovf.un',0],0xA9:['sub.ovf',0],0xAA:['sub.ovf.un',0],0xAB:['endfinally',0],0xAC:['leave',4],0xAD:['leave.s',1],0xAE:['stind.i',0],0xAF:['conv.u',0],0xB0:['arglist',0],0xB1:['ceq',0],0xB2:['cgt',0],0xB3:['cgt.un',0],0xB4:['clt',0],0xB5:['clt.un',0],0xB6:['ldftn',4],0xB7:['ldvirtftn',4],0xB8:['ldarg',2],0xB9:['ldarga',2],0xBA:['starg',2],0xBB:['ldloc',2],0xBC:['ldloca',2],0xBD:['stloc',2],0xBE:['localloc',0],0xBF:['endfilter',0],0xC0:['unaligned.',1],0xC1:['volatile.',0],0xC2:['tail.',0],0xC3:['initobj',4],0xC4:['constrained.',4],0xC5:['cpblk',0],0xC6:['initblk',0],0xC7:['no.',1],0xC8:['rethrow',0],0xCA:['sizeof',4],0xCB:['refanytype',0],0xCC:['readonly.',0] };
  const IL2: Record<number, [string, number]> = { 0x00:['ldtoken',4],0x01:['ldarg',2],0x02:['ldarga',2],0x03:['starg',2],0x04:['ldloc',2],0x05:['ldloca',2],0x06:['stloc',2],0x07:['localloc',0],0x08:['endfilter',0],0x09:['unaligned.',1],0x0A:['volatile.',0],0x0B:['tail.',0],0x0C:['initobj',4],0x0D:['constrained.',4],0x0E:['cpblk',0],0x0F:['initblk',0],0x10:['no.',1],0x11:['rethrow',0],0x12:['sizeof',4],0x13:['refanytype',0],0x14:['readonly.',0] };

  function resolveToken(tok: number): string {
    const table = tok >>> 24, idx = tok & 0xFFFFFF;
    if (table === 0x70) return `str "${getUserString(idx)}"`;
    if (table === 0x0A) { const m = memberRefs[idx-1]; return m ? `${m.name}()` : `memberref[${idx}]`; }
    if (table === 0x06) { const m = methods[idx-1]; return m ? m.name : `method[${idx}]`; }
    if (table === 0x02) { const t = types[idx-1]; return t ? (t.ns ? t.ns + '.' : '') + t.name : `typedef[${idx}]`; }
    if (table === 0x01) { const t = types[idx-1]; return t ? t.name : `typeref[${idx}]`; }
    return `token(0x${tok.toString(16)})`;
  }
  function getUserString(idx: number): string {
    const us = streams['#US'] ? rvaToOff(metadataRva + streams['#US'].rva, sections) : -1;
    if (us < 0) return '';
    let q = us + idx;
    let len = 0, shift = 0;
    do { const b = d[q++]; len |= (b & 0x7F) << shift; shift += 7; } while (d[q-1] & 0x80);
    let s = '';
    for (let i = 0; i < len - 1; i += 2) { const c = d[q+i] | (d[q+i+1]<<8); s += c === 1 ? '' : String.fromCharCode(c); }
    return s;
  }

  // ── decode method bodies ──
  const ilLines: string[] = [];
  const pseudoLines: string[] = [];
  let instrCount = 0;

  ilLines.push(`// Assembly: ${getStr(1) || 'unknown'}`);
  ilLines.push(`// Types: ${rows[2] || 0}, Methods: ${rows[6] || 0}, Fields: ${rows[4] || 0}, MemberRefs: ${rows[10] || 0}`);
  ilLines.push('');

  types.forEach((td, ti) => {
    const fullName = (td.ns ? td.ns + '.' : '') + td.name;
    pseudoLines.push(`class ${fullName} {`);
    ilLines.push(`// ── ${fullName} ──`);
    const nextMethodList = ti + 1 < types.length ? types[ti+1].methodList : (rows[6] || 0) + 1;
    for (let mi = td.methodList; mi < nextMethodList; mi++) {
      const m = methods[mi - 1];
      if (!m) continue;
      const bodyOff = rvaToOff(m.rva, sections);
      if (bodyOff < 0) { ilLines.push(`  // ${m.name}: no body (abstract/native)`); continue; }
      ilLines.push(`  .method ${m.name} {`);
      pseudoLines.push(`  // method: ${m.name}`);
      let q = bodyOff;
      const b = d[q];
      let maxStack = 0, codeSize = 0, localSig = 0;
      if (b & 0x3) { // fat header
        const flags = u16(d, q) & 0xFFF;
        maxStack = u16(d, q+2);
        codeSize = u32(d, q+4);
        localSig = u32(d, q+8);
        q += 12 + ((u16(d,q) >> 12) * 4);
      } else {
        maxStack = d[q+1]; codeSize = d[q+2] | (d[q+3]<<8); q += 4;
      }
      const codeStart = q;
      ilLines.push(`    // maxstack ${maxStack}, code ${codeSize} bytes, locals 0x${localSig.toString(16)}`);
      pseudoLines.push(`  ${m.name}() {`);
      const stack: string[] = [];
      let indent = '    ';
      let pc = 0;
      while (pc < codeSize) {
        let op = d[codeStart + pc]; pc++;
        let name = '', size = 0;
        if (op === 0xFE) { op = d[codeStart + pc]; pc++; const e = IL2[op] || [`fe_${op.toString(16)}`,0]; name = e[0]; size = e[1]; }
        else { const e = IL[op] || [`op_${op.toString(16)}`,0]; name = e[0]; size = e[1]; }
        let operand = '';
        if (size === -1) { // switch
          const n = u32(d, codeStart+pc); pc += 4 + n*4;
          operand = `<switch ${n}>`;
        } else if (size === 1) { operand = d[codeStart+pc].toString(); pc += 1; }
        else if (size === 2) { operand = u16(d, codeStart+pc).toString(); pc += 2; }
        else if (size === 4) { const t = u32(d, codeStart+pc); operand = resolveToken(t); pc += 4; }
        else if (size === 8) { operand = u64(d, codeStart+pc).toString(); pc += 8; }
        ilLines.push(`    IL_${(pc-size-1).toString().padStart(4,'0')}: ${name.padEnd(14)} ${operand}`);
        instrCount++;
        // pseudo
        switch (name) {
          case 'ldstr': stack.push(operand.replace(/^str /,'')); break;
          case 'ldc.i4.m1': stack.push('-1'); break;
          case 'ldc.i4.0': stack.push('0'); break;
          case 'ldc.i4.1': stack.push('1'); break;
          case 'ldc.i4.2': stack.push('2'); break;
          case 'ldc.i4.3': stack.push('3'); break;
          case 'ldc.i4.4': stack.push('4'); break;
          case 'ldc.i4.5': stack.push('5'); break;
          case 'ldc.i4.6': stack.push('6'); break;
          case 'ldc.i4.7': stack.push('7'); break;
          case 'ldc.i4.8': stack.push('8'); break;
          case 'ldc.i4.s': case 'ldc.i4': stack.push(operand); break;
          case 'ldnull': stack.push('null'); break;
          case 'ldarg.0': stack.push('this'); break;
          case 'ldarg.1': stack.push('arg1'); break;
          case 'ldarg.2': stack.push('arg2'); break;
          case 'ldarg.3': stack.push('arg3'); break;
          case 'ldloc.0': stack.push('loc0'); break;
          case 'ldloc.1': stack.push('loc1'); break;
          case 'ldloc.2': stack.push('loc2'); break;
          case 'ldloc.3': stack.push('loc3'); break;
          case 'stloc.0': { const v = stack.pop()||'?'; pseudoLines.push(`${indent}loc0 = ${v};`); break; }
          case 'stloc.1': { const v = stack.pop()||'?'; pseudoLines.push(`${indent}loc1 = ${v};`); break; }
          case 'stloc.2': { const v = stack.pop()||'?'; pseudoLines.push(`${indent}loc2 = ${v};`); break; }
          case 'stloc.3': { const v = stack.pop()||'?'; pseudoLines.push(`${indent}loc3 = ${v};`); break; }
          case 'add': { const b2=stack.pop()||'?',a2=stack.pop()||'?'; stack.push(`(${a2} + ${b2})`); break; }
          case 'sub': { const b2=stack.pop()||'?',a2=stack.pop()||'?'; stack.push(`(${a2} - ${b2})`); break; }
          case 'mul': { const b2=stack.pop()||'?',a2=stack.pop()||'?'; stack.push(`(${a2} * ${b2})`); break; }
          case 'div': { const b2=stack.pop()||'?',a2=stack.pop()||'?'; stack.push(`(${a2} / ${b2})`); break; }
          case 'rem': { const b2=stack.pop()||'?',a2=stack.pop()||'?'; stack.push(`(${a2} % ${b2})`); break; }
          case 'and': { const b2=stack.pop()||'?',a2=stack.pop()||'?'; stack.push(`(${a2} & ${b2})`); break; }
          case 'or': { const b2=stack.pop()||'?',a2=stack.pop()||'?'; stack.push(`(${a2} | ${b2})`); break; }
          case 'xor': { const b2=stack.pop()||'?',a2=stack.pop()||'?'; stack.push(`(${a2} ^ ${b2})`); break; }
          case 'ceq': { const b2=stack.pop()||'?',a2=stack.pop()||'?'; stack.push(`(${a2} == ${b2})`); break; }
          case 'cgt': { const b2=stack.pop()||'?',a2=stack.pop()||'?'; stack.push(`(${a2} > ${b2})`); break; }
          case 'clt': { const b2=stack.pop()||'?',a2=stack.pop()||'?'; stack.push(`(${a2} < ${b2})`); break; }
          case 'call': case 'callvirt': {
            const args: string[] = [];
            // heuristic: pop until we hit something non-arg — just pop 1 for demo
            const fn = operand;
            const arg = stack.pop();
            stack.push(`${fn}${arg ? `(${arg})` : '()'}`);
            break;
          }
          case 'newobj': { const fn = operand; stack.push(`new ${fn}()`); break; }
          case 'ret': { const v = stack.pop(); pseudoLines.push(`${indent}return${v ? ' ' + v : ''};`); break; }
          case 'br.s': case 'br': pseudoLines.push(`${indent}goto ${operand};`); break;
          case 'brfalse.s': case 'brfalse': { const c = stack.pop()||'?'; pseudoLines.push(`${indent}if (!${c}) goto ${operand};`); break; }
          case 'brtrue.s': case 'brtrue': { const c = stack.pop()||'?'; pseudoLines.push(`${indent}if (${c}) goto ${operand};`); break; }
          case 'pop': stack.pop(); break;
          case 'dup': { const t = stack[stack.length-1]||'?'; stack.push(t); break; }
          case 'ldfld': case 'ldsfld': { const o = stack.pop(); stack.push(`${o||'this'}.${operand}`); break; }
          case 'stfld': case 'stsfld': { const v = stack.pop()||'?'; const o = stack.pop(); pseudoLines.push(`${indent}${o||'this'}.${operand} = ${v};`); break; }
          case 'throw': { const v = stack.pop()||'?'; pseudoLines.push(`${indent}throw ${v};`); break; }
        }
      }
      pseudoLines.push(`  }`);
      ilLines.push(`  }`);
    }
    pseudoLines.push('}');
    pseudoLines.push('');
  });

  return {
    detected: '.NET assembly (C#)',
    pseudo: pseudoLines.join('\n'),
    il: ilLines.join('\n'),
    strings: extractStrings(d),
    hexPreview: hexDump(d),
    stats: { functions: rows[6] || 0, instructions: instrCount, strings: extractStrings(d).length, size: d.length }
  };
}
