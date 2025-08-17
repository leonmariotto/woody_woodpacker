/* start_custom.S */
    .text
    .globl _start
    .type  _start, @function
_start:
    endbr64                 /* if CET enabled; harmless otherwise */
    xor     %ebp, %ebp
    mov     %rdx, %r9       /* r9 = rtld_fini (set by the loader); rdx also held envp-ish */
    pop     %rsi            /* rsi = argc  (from stack top) */
    mov     %rsp, %rdx      /* rdx = argv  (stack now points to argv[0]) */
    and     $-16, %rsp      /* 16-byte stack alignment */
    push    %rax            /* padding */
    push    %rsp            /* 7th arg: stack_end */
    xor     %r8d, %r8d      /* 5th arg: fini = NULL (glibc ≥ 2.34) */
    xor     %ecx, %ecx      /* 4th arg: init = NULL (glibc ≥ 2.34) */

    # --- Choose main function based on boot_mode ---
    mov     boot_mode(%rip), %eax   # load boot_mode
    cmp     $0xCAFEBABE, %eax
    jne     1f                           # if !=0xCAFEBABE, jump to alt_main
    lea main(%rip), %rdi                 # rdi = main
    jmp     2f
1:  lea launch(%rip), %rdi               # rdi = launch
2:
    call    *__libc_start_main@GOTPCREL(%rip)
    hlt                     /* not reached */
    .size _start, .-_start

    /* Choose what you want to call “main” */
    .extern main
    .extern launch
    .extern boot_mode

    .section .note.GNU-stack,"",@progbits
