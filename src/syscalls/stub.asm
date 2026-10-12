;
; Indirect syscall gate for x64.
;
; C wrappers store SSN and gadget address in globals before calling sc_gate.
; sc_gate is called with the real Nt* args in rcx, rdx, r8, r9, stack —
; it sets eax=SSN, r10=rcx (kernel ABI), then jumps to the gadget
; (a syscall;ret sequence inside ntdll).
;

EXTERN g_ssn:DWORD
EXTERN g_gadget:QWORD

.code

sc_gate PROC
    mov     r10, rcx                ; NT kernel calling convention
    mov     eax, DWORD PTR [g_ssn]  ; syscall number
    mov     r11, QWORD PTR [g_gadget]
    jmp     r11                     ; -> syscall; ret in ntdll
sc_gate ENDP

END
