# Decompiler Pro

Multi-language decompiler web app. Deploy to Vercel in one click.

## Features
- **Lua 5.1–5.4 + LuaJIT** — full bytecode parser, opcode disassembler, pseudocode decompiler
- **C# / .NET** — PE parser, metadata tables (#~ stream), IL disassembler, C#-like pseudocode reconstruction
- **C++ / Native** — PE32+ and ELF64 parser, x86-64 disassembler, C-like pseudocode
- Hex dump + string extraction for all formats
- Auto-detect or force language

## Deploy
1. Push this folder to a Git repo (or run `vercel` CLI in it)
2. Import in Vercel — zero config needed
3. Done

## Local dev
```bash
npm install
npm run dev
```

## API
`POST /api/decompile`
```json
{ "filename": "app.dll", "data": "<base64>", "lang": "auto" }
```
`lang`: `auto` | `lua` | `cs` | `cpp`
