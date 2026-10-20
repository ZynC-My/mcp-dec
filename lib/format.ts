
export function hex(n: number, w = 8): string {
  return '0x' + (n >>> 0).toString(16).padStart(w, '0').toUpperCase();
}
export function u8(d: Uint8Array, o: number) { return d[o]; }
export function u16(d: Uint8Array, o: number) { return d[o] | (d[o+1] << 8); }
export function u32(d: Uint8Array, o: number) { return (d[o] | (d[o+1]<<8) | (d[o+2]<<16) | (d[o+3]<<24)) >>> 0; }
export function u64(d: Uint8Array, o: number): bigint {
  return BigInt(u32(d,o)) | (BigInt(u32(d,o+4)) << 32n);
}
export function ascii(d: Uint8Array, o: number, len: number): string {
  let s = '';
  for (let i = 0; i < len && o+i < d.length; i++) s += String.fromCharCode(d[o+i]);
  return s;
}
export function cstr(d: Uint8Array, o: number): string {
  let s = '';
  while (o < d.length && d[o] !== 0) s += String.fromCharCode(d[o++]);
  return s;
}
export function extractStrings(d: Uint8Array, minLen = 4): string[] {
  const out: string[] = [];
  let cur = '';
  for (let i = 0; i < d.length; i++) {
    const b = d[i];
    if (b >= 32 && b < 127) cur += String.fromCharCode(b);
    else { if (cur.length >= minLen) out.push(cur); cur = ''; }
  }
  if (cur.length >= minLen) out.push(cur);
  return out.slice(0, 500);
}
export function hexDump(d: Uint8Array, max = 256): string {
  const lines: string[] = [];
  const n = Math.min(d.length, max);
  for (let i = 0; i < n; i += 16) {
    const chunk = Array.from(d.slice(i, i+16));
    const hexs = chunk.map(b => b.toString(16).padStart(2,'0')).join(' ');
    const asc = chunk.map(b => b >= 32 && b < 127 ? String.fromCharCode(b) : '.').join('');
    lines.push(i.toString(16).padStart(8,'0') + '  ' + hexs.padEnd(47) + '  ' + asc);
  }
  if (d.length > max) lines.push(`... (${d.length - max} more bytes)`);
  return lines.join('\n');
}
