
import { NextRequest, NextResponse } from 'next/server';
import { isLuaBytecode, decompileLua } from '@/lib/lua';
import { isDotNet, decompileDotNet } from '@/lib/dotnet';
import { isPE, isELF, parsePE, parseELF } from '@/lib/native';

export const runtime = 'nodejs';
export const maxDuration = 60;

export async function POST(req: NextRequest) {
  try {
    const { filename, data, lang } = await req.json();
    if (!data) return NextResponse.json({ error: 'No data' }, { status: 400 });

    const bin = Buffer.from(data, 'base64');
    const d = new Uint8Array(bin);
    const name = (filename || '').toLowerCase();
    const forced = lang || 'auto';

    let result;
    if (forced === 'lua' || (forced === 'auto' && (isLuaBytecode(d) || name.endsWith('.luac') || name.endsWith('.jit')))) {
      result = decompileLua(d);
    } else if (forced === 'cs' || (forced === 'auto' && (isDotNet(d) || name.endsWith('.exe') || name.endsWith('.dll')))) {
      if (isDotNet(d)) result = decompileDotNet(d);
      else if (isPE(d)) result = parsePE(d);
      else throw new Error('Not a .NET assembly or PE file');
    } else if (forced === 'cpp' || (forced === 'auto' && (isPE(d) || isELF(d) || name.endsWith('.so') || name.endsWith('.elf') || name.endsWith('.bin')))) {
      if (isELF(d)) result = parseELF(d);
      else if (isPE(d)) result = parsePE(d);
      else throw new Error('Unknown binary format');
    } else {
      // fallback: try Lua, then .NET, then native
      if (isLuaBytecode(d)) result = decompileLua(d);
      else if (isDotNet(d)) result = decompileDotNet(d);
      else if (isELF(d)) result = parseELF(d);
      else if (isPE(d)) result = parsePE(d);
      else throw new Error('Unrecognized format. Try forcing a language.');
    }

    return NextResponse.json(result);
  } catch (e: any) {
    return NextResponse.json({ error: e.message || 'Decompilation failed' }, { status: 500 });
  }
}
