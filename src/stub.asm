; Position-independent stub block for in-process EAT patching.
;   nasm -f bin -l stub.lst -o stub.bin stub.asm
;
; Every export slot of the target DLL gets a stub.  A stub logs the call and
; then either forwards to the real implementation (default) or answers with a
; canned value, selected per slot by a cfg word the injector writes.
;
; Slots are addressed by their EAT index only (f00..f29), so this file does not
; depend on the target's export names and survives a rename.  The injector
; walks the export address table by index too, which keeps both sides aligned
; by position instead of by string.
;
;   f00..f29   stub bodies, one per EAT slot
;   c00..c15   cfg words (0 = forward, 1 = answer with the canned value)
;   r00..r29   slots for the real function addresses, filled by the injector
;   s0..s6     canned string buffers
;
; Forwarding uses `jmp eax` so the caller's stack frame reaches the original
; function untouched; the original then does its own `ret N`.
;
; The blob is allocated inside the patched process.  The injector writes the
; real_* table with absolute addresses (thunk targets or trampolines, never the
; patched entry itself, which would recurse) and rewrites the EAT entries.
BITS 32
org 0

%define LOG_MAX 256

%macro BASEP 0
    call %%a
%%a:
    pop ebx
    sub ebx, %%a
%endmacro

; %1 = id  (records [id][a1][a2][0] into log_buf)
%macro LOG 1
%if %1 = 2
    ; id 2 is a high-frequency poll; logging it would flush the ring buffer
%else
    push eax
    push ecx
    push edx
    push esi
    mov esi, [ebx + log_idx]
    cmp esi, LOG_MAX
    jae %%skip
    mov eax, [esp + 24]        ; a1: 4 regs (16) + saved ebx (4) + return address (4)
    mov ecx, [esp + 28]        ; a2
    ; collapse runs of identical polling calls
    test esi, esi
    jz %%store
    lea edx, [esi - 1]
    shl edx, 4
    lea edx, [edx + ebx + log_buf]
    cmp dword [edx], %1
    jne %%store
    cmp dword [edx + 4], eax
    jne %%store
    cmp dword [edx + 8], ecx
    jne %%store
    jmp %%skip
%%store:
    mov edx, esi
    shl edx, 4
    lea edx, [edx + ebx + log_buf]
    mov dword [edx], %1
    mov [edx + 4], eax
    mov [edx + 8], ecx
    mov dword [edx + 12], 0
    inc dword [ebx + log_idx]
%%skip:
    pop esi
    pop edx
    pop ecx
    pop eax
%endif
%endmacro

%macro FAKE_INT 4                 ; slot, id, cfg_off, argbytes
stub_%1:
    push ebx
    BASEP
    LOG %2
    cmp dword [ebx + %3], 0
    jne %%fake
    mov eax, [ebx + r%1]
    pop ebx
    jmp eax
%%fake:
    mov eax, 1
    pop ebx
    ret %4
%endmacro

%macro FAKE_STR 5                 ; slot, id, cfg_off, string index, argbytes
stub_%1:
    push ebx
    BASEP
    LOG %2
    cmp dword [ebx + %3], 0
    jne %%fake
    mov eax, [ebx + r%1]
    pop ebx
    jmp eax
%%fake:
    lea eax, [ebx + s%4]
    pop ebx
    ret %5
%endmacro

%macro FWD 2                      ; slot, id
stub_%1:
    push ebx
    BASEP
    LOG %2
    mov eax, [ebx + r%1]
    pop ebx
    jmp eax
%endmacro

; ---------------------------------------------------------------------------
; slots that can be answered locally.  argcount in the last column is the
; stdcall argument size in bytes, taken from each signature.
; ---------------------------------------------------------------------------
FAKE_INT f21,   1, c00,       0   ; 0 args
FAKE_INT f08,   2, c01,       0
FAKE_INT f02,   3, c02,       0
FAKE_STR f20,   4, c03,    0,  0   ; returns char*, 0 args
FAKE_STR f14,   5, c04,    1,  0
FAKE_STR f12,   6, c05,    2,  0
FAKE_INT f17,   9, c07,       4   ; 1 arg
FAKE_INT f09,  10, c08,      20   ; 5 args
FAKE_INT f24,  11, c09,       8   ; 2 args
FAKE_INT f26,  12, c10,      20
FAKE_INT f25,  13, c11,      12   ; 3 args
FAKE_INT f29,  14, c12,      12
FAKE_INT f01,  15, c13,      20
FAKE_INT f28,  16, c14,       8

; f13(ptr): the caller frees every string it receives, but the canned strings
; live in this blob, not on the DLL heap.  Handing those to the real free()
; corrupts the heap, so pointers inside the blob are answered locally.
stub_f13:
    push ebx
    BASEP
    LOG 8
    mov eax, [esp + 8]
    cmp dword [ebx + c15], 0
    jne .local
    lea ecx, [ebx + end_of_block]
    cmp eax, ebx
    jb .forward
    cmp eax, ecx
    jb .local
.forward:
    mov eax, [ebx + rf13]
    pop ebx
    jmp eax
.local:
    xor eax, eax
    pop ebx
    ret 4

; f06(int) selects one of four canned strings by index
stub_f06:
    push ebx
    BASEP
    LOG 7
    cmp dword [ebx + c06], 0
    jne .fake
    mov eax, [ebx + rf06]
    pop ebx
    jmp eax
.fake:
    mov ecx, [esp + 8]
    cmp ecx, 1
    je .g1
    cmp ecx, 2
    je .g2
    cmp ecx, 3
    je .g3
    lea eax, [ebx + s6]
    pop ebx
    ret 4
.g1:
    lea eax, [ebx + s3]
    pop ebx
    ret 4
.g2:
    lea eax, [ebx + s4]
    pop ebx
    ret 4
.g3:
    lea eax, [ebx + s5]
    pop ebx
    ret 4

; ---- pure forwarders ----
FWD f00,  20
FWD f03,  21
FWD f04,  22
FWD f05,  23
FWD f07,  24
FWD f10,  25
FWD f11,  26
FWD f15,  27
FWD f16,  28
FWD f18,  29
FWD f19,  30
FWD f22,  31
FWD f23,  32
FWD f27,  33

; ================= data =================
align 16
log_idx:      dd 0
align 16
log_buf:      times LOG_MAX*16 db 0

align 16
c00: dd 1
c01: dd 0
c02: dd 0
c03: dd 1
c04: dd 1
c05: dd 0
c06: dd 1
c07: dd 0
c08: dd 1
c09: dd 0
c10: dd 0
c11: dd 0
c12: dd 0
c13: dd 0
c14: dd 0
c15: dd 0

align 16
rf00: dd 0
rf01: dd 0
rf02: dd 0
rf03: dd 0
rf04: dd 0
rf05: dd 0
rf06: dd 0
rf07: dd 0
rf08: dd 0
rf09: dd 0
rf10: dd 0
rf11: dd 0
rf12: dd 0
rf13: dd 0
rf14: dd 0
rf15: dd 0
rf16: dd 0
rf17: dd 0
rf18: dd 0
rf19: dd 0
rf20: dd 0
rf21: dd 0
rf22: dd 0
rf23: dd 0
rf24: dd 0
rf25: dd 0
rf26: dd 0
rf27: dd 0
rf28: dd 0
rf29: dd 0

align 16
s0: times 256 db 0
s1: times 256 db 0
s2: times 256 db 0
s3: times 256 db 0
s4: times 256 db 0
s5: times 256 db 0
s6: times 256 db 0

; ---- self describing symbol table ----
; layout: magic, count, then `count` dwords of blob-relative offsets.
; order: 30 stub bodies, 16 cfg words, 30 real slots, 7 string buffers.
align 16
symtab:
    dd 0x424B4150                    ; 'PAKB'
    dd 83
    ; --- stub bodies, index 0..29 (EAT order) ---
    dd stub_f00, stub_f01, stub_f02, stub_f03, stub_f04
    dd stub_f05, stub_f06, stub_f07, stub_f08, stub_f09
    dd stub_f10, stub_f11, stub_f12, stub_f13, stub_f14
    dd stub_f15, stub_f16, stub_f17, stub_f18, stub_f19
    dd stub_f20, stub_f21, stub_f22, stub_f23, stub_f24
    dd stub_f25, stub_f26, stub_f27, stub_f28, stub_f29
    ; --- cfg words, index 30..45 ---
    dd c00, c01, c02, c03, c04
    dd c05, c06, c07, c08, c09
    dd c10, c11, c12, c13, c14
    dd c15
    ; --- real slots, index 46..75 ---
    dd rf00, rf01, rf02, rf03, rf04
    dd rf05, rf06, rf07, rf08, rf09
    dd rf10, rf11, rf12, rf13, rf14
    dd rf15, rf16, rf17, rf18, rf19
    dd rf20, rf21, rf22, rf23, rf24
    dd rf25, rf26, rf27, rf28, rf29
    ; --- string buffers, index 76..82 ---
    dd s0, s1, s2, s3, s4, s5, s6

end_of_block:
