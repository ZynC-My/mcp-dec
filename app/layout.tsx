import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'Decompiler Pro — Lua · C# · C++',
  description: 'Multi-language decompiler & disassembler. Lua 5.1–5.4, LuaJIT, .NET IL, native x86-64.'
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
