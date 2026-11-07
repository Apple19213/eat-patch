> Reverse-engineering notes. The target and its SDK are referred to as TARGET and
> AUTH.dll throughout. No original binaries, decompiler output, or fragments
> thereof are included. Every number below was measured and is reproducible.

# From an empty managed layer to an in-process EAT patch

The full decision trail: what I did at each step, why, and which evidence killed
which hypothesis.

---

## 0. Starting conditions

A commercial Chinese tool (TARGET, .NET WinForms, ~32 MB main executable) that
shows a login window on startup and wants an account or a licence key. It ships
with one native licensing DLL (AUTH.dll, ~1.4 MB).

Goal: reach the main window and all features without entering a key.

---

## 1. The managed layer: why editing IL is pointless

`ilspycmd -p` produced 1159 `.cs` files, 43 MB. Characteristics:

- randomized class and field names (`A0V7DNekoTbO90lxXA9d`)
- control-flow flattening (`num/num2/num3` state machines)
- two `<Module>{GUID}` types

The important observation: **the method bodies are essentially empty**.

```
10384 method bodies inside TARGET.Form120 have Code size: 4
  → nop; nop; ldc.i4.1; ret     (returns true)
  → nop; nop; ldnull; ret       (returns null)
```

Checked the raw bytes on disk to rule out a decompiler artifact:

```
... 13 30 04 00 04 00 00 00 00 00 00 00 00 00 17 2a ...
      ^^^^^ method header         ^^^^^^^^^^^ code: nop nop ldc.i4.1 ret
```

**Conclusion**: the protector stripped or replaced the bodies. There is nothing
to patch statically.

Body size histogram (after parsing the PE section headers correctly):

| category | count |
|---|---|
| invalid / shell (code size ≤ 4) | 13019 |
| actually executable | **2619** |

`Form120` has 11 bytes of real IL — exactly the 18 `DllImport` declarations.

> Detour worth recording: my first section-header parser read
> `Name(8)+VirtualSize+VirtualAddress+SizeOfRawData+PointerToRawData` in the wrong
> order, treating `VirtualSize` as `VirtualAddress`, which produced the absurd
> figure "2.8e11 bytes of real IL". The correct form is
> `struct.unpack_from('<IIII', d, secoff + i*40 + 8)` → `(vs, va, rs, ro)`.

---

## 2. Finding the real entry point: 18 P/Invokes

Searching the whole assembly for `pinvokeimpl` returns exactly one site:

```csharp
[DllImport("AUTH.dll", CharSet=Ansi, ExactSpelling=true, SetLastError=true)]
public static extern int f21();                          // trial
public static extern int f24(ref string, ref string);    // login
public static extern native int f06(int);                // info query
public static extern native int f20();                   // tip string
public static extern native int f14();                   // expiry time
// ... 18 total
```

**This is the turning point**: the managed side is a UI shell; every licensing
decision happens in native code.

Parameter semantics, also settled here:

- `string& marshal(byvalstr)` = out parameter into a caller-allocated buffer
- `native int` return = **ANSI string pointer allocated by the DLL**, must be
  released with `f13`

Slot map used from here on:

| slot | role |
|---|---|
| f01 | polling register |
| f02 | polling clock |
| f06 | info query (1 = notice text, 2/3/4 = numeric fields) |
| f08 | registration state |
| f13 | string free |
| f14 | expiry time |
| f20 | tip string |
| f21 | trial |

---

## 3. First attempt: replace the DLL. Fails.

| experiment | result |
|---|---|
| original DLL | starts normally, login window appears |
| rename the DLL away | `0xE0434352` (unhandled CLR exception, DllNotFoundException) |
| original + 1 byte XOR | **`rc=0`, silent exit after 1.10 s, no window, no log** |
| original + 1 zero byte appended | **`rc=0`, silent exit after 1.10 s** |
| flip a dead byte in `.rsrc` slack | same |
| hand-written 30-export forwarding proxy | same |

Reasoning chain:

1. Not PE checksum — the original has `stored=0x0`; it was never filled in.
2. Not a baked-in hash — md5/sha1/sha256/crc32 of the file and of each section,
   in raw, hex, and upper-hex form, searched across the full 32 MB exe: **zero
   hits**.
3. Not the DLL checking itself — a tampered copy loaded under a different name by
   a standalone probe works fine.
4. So the check covers **every byte plus the exact length**, and it fails by
   calling `Exit` rather than throwing, which is why nothing reaches the event log.

**Conclusion**: no file-level change survives. The patch has to live in memory.

---

## 4. In-memory architecture

### 4.1 Rewriting the EAT

AUTH.dll's export directory sits at RVA `0x38100`, 30 exports. Two entry shapes:

| shape | bytes | count |
|---|---|---|
| thunk | `56 57 53 E8 rel32 5B 5F 5E C3` | 9 |
| direct wrapper | `56 57 53 8D 74 24 10 83 EC ..` | 21 |

Both handled the same way: overwrite the first 5 bytes with `E9 rel32` pointing
at our stub.

### 4.2 The stub blob

`nasm -f bin` emits a position-independent blob (~10 KB) that gets
`VirtualAllocEx`'d into the target process.

Three design decisions:

**Self-location** — each stub does
`push ebx / call .a / .a: pop ebx / sub ebx,.a` to learn the blob's own address,
so it can live anywhere.

**Forwarding must use jmp** — the stub is stdcall (`ret N*4`) and so is the
target. `call` followed by a return pops the arguments twice; the symptom is
`0xC0000005`. It has to be:

```asm
mov eax, [ebx + r21]
pop ebx
jmp eax
```

**Indexed, not named** — stubs are `f00`..`f29`, cfg words `c00`..`c15`, real
address slots `r00`..`r29`, string buffers `s0`..`s6`. The injector walks the
export address table by ordinal, so the two sides agree purely on position and
the source contains no target-specific identifiers.

**Self-describing symbol table** — the blob ends with `PAKB`, a count, and 83
dwords of offsets. The injector reads it at runtime, so editing `stub.asm` never
requires touching the injector.

### 4.3 It runs, and recurses forever

Filling the `r*` slots with `base + rva` — that is, with **the entries we had
just overwritten** — makes a stub jump back to its own entry, which jumps back
to the stub. Infinite recursion.

Fix: build trampolines, one per shape.

- thunk: `real = entry + 8 + rel32`
- direct wrapper: copy `DisplacedLength(code)` bytes into the blob, fix up any
  `E8`/`E9` displacement inside them, append `E9` back to `entry + n`

`DisplacedLength` needs a minimal x86-32 length decoder. Covering `push/pop`,
`8D 74 24 xx`, `83 EC xx`, `B8-BF`, `E8/E9/EB` and `0F 8x` is enough for the
prologues that actually occur.

---

## 5. Three things that kept the main window from appearing

### Trap 1: f13 frees our static strings

Returning a convincing string from f20 killed the process instantly. f20 hands
back a static buffer inside the blob, but the caller follows the contract and
calls `f13(ptr)`, whose real implementation tries to `free` memory that never
came from `malloc`.

Fix: f13 checks whether the pointer lands inside `[blob, blob_end)` first:

```asm
mov eax, [esp + 8]
cmp eax, ebx
jb  .forward          ; below the blob → belongs to the real DLL
lea ecx, [ebx + blob_end]
cmp eax, ecx
jb  .local            ; inside the blob → ours, answer locally
```

### Trap 2: f06(2/3/4) goes through `Double.Parse`

The patch applied, `Right` was produced, and the main window still never showed
up. A hidden control in the login window held an unhandled exception:

> Invalid cast from string "" to type "Double".

`f06(1)` is the notice text, but `f06(2/3/4)` are numeric fields. Returning
`99999` made the window appear immediately.

### Trap 3: the window is on screen but "invisible"

Process alive, `IsWindowVisible=1`, `cloaked=0`, screenshots proving content was
rendered — and the user still could not see it. Three things stacked:

1. the main window has `style=0x16030000`, **no caption and no border**, so it
   does not look like a window
2. the launcher exited after 800 ms, so the console flashed and vanished
3. old code called `SetWindowPos(HWND_TOPMOST)` and then `HWND_NOTOPMOST`
   immediately after, which pushed the just-raised window back behind the console

Separately, the app intercepts external moves in `WM_WINDOWPOSCHANGING`
(`SetWindowPos(...,0x40)` returns **0**). Adding `SWP_NOSENDCHANGING(0x0400)`
makes it return 1 and the rect changes immediately.

---

## 6. Final verification

Call sequence on the success path, 13 calls:

```
f21 → f06(2) → f13 → f06(1) → f13 → f06(3) → f13 → f06(4) → f13
    → f20 → f13 → f14 → f13
```

Note that f02 is a high-frequency poll — it fills the 256-entry ring buffer
instantly — and so is f01. Both have to be skipped or de-duplicated in the log,
otherwise the one-shot calls are never visible.

Runtime check:

```
f21    e9196581fc75fdff  PATCHED
f20    e9b16581fcf2ffff  PATCHED
f06    e9e56b81fc241083  PATCHED
f08    e9e46481fccaffff  PATCHED
```

Stability: 55 samples over 600 s at 10 s intervals. No re-authentication, no
lost authorisation, no crash. The on-disk AUTH.dll md5 never changed.

---

## 7. Reusable lessons

1. **Establish which layer the logic lives in first.** All managed bodies empty
   → move to native immediately instead of burning time on IL.
2. **Measure the check's granularity, do not guess.** Flip one byte, append one
   byte, touch slack — three experiments localise "whole file + exact length".
3. **Silent exit is harder to debug than an exception.** `rc=0` with no event-log
   entry means the target called `Exit` on purpose; the only way forward is to
   step around the checkpoint (in-process), not around the check.
4. **There is exactly one correct way to forward stdcall: `jmp`.**
5. **A self-describing data section** saves a lot of "change one macro and every
   offset shifts" debugging.
6. **Canned return values must obey the caller's type contract.** An empty string
   is a bomb for `Double.Parse`.
7. **"It didn't work" at the UI layer is often a visibility problem, not a patch
   problem** — separate the two with `IsWindowVisible`, a screenshot, and pixel
   statistics before touching the patch again.
