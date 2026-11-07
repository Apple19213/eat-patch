# eat-patch

In-process EAT patching for a .NET app whose licensing lives in a native DLL.

**English** | [中文](README.zh-CN.md) | [日本語](README.ja.md)

The app I was looking at ships as a managed WinForms shell plus one native
licence DLL. All the interesting logic is in the DLL; the managed side only
declares 18 `DllImport`s and draws the window. This repo is the launcher I
ended up with: it starts the app, patches the DLL's export address table in
memory, and makes the licence calls answer with canned values. Nothing on disk
is modified.

It is not a generic unpacker and it will not work on a different app without
edits. Treat it as a worked example plus a reusable stub layout.

## Why in-memory

The obvious approaches do not survive contact with the target:

| tried | result |
|---|---|
| patch managed IL | 13019 of 15638 method bodies are 4-byte stubs (`nop nop ldc.i4.1 ret`). Nothing to patch. |
| edit the DLL on disk | 1 byte flipped, or 1 byte appended, and the app exits within ~1.1 s with `rc=0`, no window, no .NET event-log entry. |
| drop in a proxy DLL with the same exports | same silent exit. |
| `App.exe.local` redirection | ignored; Win7+ disabled it without a manifest. |

Two things I could rule out along the way: PE checksum (`stored=0x0`, never
filled in) and a baked-in hash (md5/sha1/sha256/crc32 of the whole file and of
each section, searched raw and hex across the 32 MB exe — zero hits). What is
left is a check that covers every byte plus the exact file length, and bails by
calling `Exit` rather than throwing. So the only workable place to stand is
after the check has already passed: inside the live process.

## How it works

**Stub blob** (`src/stub.asm`) is `nasm -f bin` output, position independent:

```asm
BASEP:
    push ebx
    call %%a
%%a: pop ebx
    sub ebx, %%a
```

Every stub gets the blob's own address in `ebx` this way, so the injector can
`VirtualAllocEx` it anywhere without relocations.

**Slots, not names.** Stubs are labelled `f00`..`f29`, cfg words `c00`..`c15`,
real-address slots `r00`..`r29`, strings `s0`..`s6`. Both sides agree on EAT
index only, so the source has no target-specific identifiers in it. The injector
walks the export address table by ordinal and never reads a name string.

**Forwarding has to be a jmp.** Both sides are stdcall. `call` into the real
function and returning again pops the arguments twice — that shows up as
`0xC0000005`:

```asm
mov eax, [ebx + r21]
pop ebx
jmp eax
```

**r-slots point at trampolines, not at entries.** The entry is where the 5-byte
`E9` lives; point the r-slot at the entry and forwarding jumps straight back into
the stub. For thunk-shaped exports (`56 57 53 E8 rel32 5B 5F 5E C3`) the real
target is just `entry + 8 + rel32`. For the rest, copy the displaced prologue
into the blob, fix up any `E8`/`E9` inside it, append `E9` back to `entry + n`.
That needs a small x86-32 length decoder; `DisplacedLength`/`InstrLength` in
`launch.cs` cover what actually appears in prologues.

**Self-describing symbol table.** The blob ends with `PAKB`, a count, and 83
dwords. The injector finds it by scanning backwards from the end of the file.
Editing `stub.asm` does not require touching the injector, and a stale offset
cannot silently corrupt the wrong word.

## Two things that cost real time

`f13` is the string free function. The caller frees every pointer it receives,
but the canned strings live in the blob rather than the DLL heap, so passing
them to the real free corrupts the heap and the process dies on the spot. The
stub checks whether the pointer falls inside `[blob, end_of_block)` and answers
locally if it does.

`f06(2)`, `f06(3)`, `f06(4)` are parsed as `Double` by the caller. Returning
empty strings throws inside a message loop, and the visible symptom is "patched,
licence looks OK, main window never appears" — easy to misread as the patch not
applying. Numbers in those three slots and the window shows up.

## Build

Needs `nasm` and the .NET Framework compiler, both already present on a stock
Windows box.

```bat
build\build.bat
```

or by hand:

```bat
nasm -f bin -l build\stub.lst -o build\stub.bin src\stub.asm

%WINDIR%\Microsoft.NET\Framework\v4.0.30319\csc.exe ^
  -nologo -target:winexe -platform:x86 -optimize+ ^
  -out:build\launcher.exe ^
  -resource:build\stub.bin,stub.bin src\launch.cs
```

`-target:winexe` matters: exe subsystem pops a console window, winexe stays
silent and only surfaces a `MessageBoxW` on failure.

## Use

```
launcher.exe                    silent: find app, inject, trigger, un-topmost, exit
launcher.exe --verbose          keep a console and print the four steps
launcher.exe "D:\path\to\app"   explicit directory; one level of subdirs is searched
```

It looks for the real executable by size — an installer shipped under the same
name is ~52 MB and gets skipped — and requires the native DLL plus the
`Resources` folder to be next to it. If the app is not where it expects, it says
so in a message box instead of failing silently.

## Pointing it at something else

Two constants at the top of `src/launch.cs`:

```csharp
const string AppName   = "TARGET";
const string TargetDll = "AUTH.dll";
```

Then rewrite the slot table in `src/stub.asm` to match the target's exports:
which slots answer locally, their argument byte counts, and the layout of the
cfg block. `CfgOn` and `StrInit` in `launch.cs` select behaviour by slot index.

## Known limits

- 32-bit only. The target is x86 and so is the injection code.
- Export table must be small and non-forwarded; the ordinal walk assumes
  `AddressOfFunctions[i]` is a plain RVA.
- One target, one Windows build. Behaviour under a packer that re-protects pages
  after startup is untested.
- The `--verbose` mode still leaves the app's own window management quirks: the
  main window has no caption (`style=0x16030000`) and refuses external moves
  unless `SWP_NOSENDCHANGING` is set.

## Further reading

- [Technical write-up (English)](docs/analysis.md) — the full decision trail,
  every experiment that failed and why.
- [技术分析（中文）](docs/技术分析.md) — same content in Chinese.

## What is not in here

No target binary, no DLL, no installer, no decompiler output, no dumped memory.
Only code I wrote and numbers I measured.

## License

MIT
