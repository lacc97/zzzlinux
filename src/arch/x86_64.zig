/// The equivalent C prototype of this function is
///
///     usize clone3(struct clone_args *cl_args, usize size,
///                  i32 (*func)(void *arg), void* arg);
///
/// such that the parameters are passed in registers as
///
///     rdi: cl_args
///     rsi: size
///     rdx: func
///     rcx: arg
///
/// whereas the kernel expects
///
///     rax: SYS_clone3
///     rdi: cl_args
///     rsi: size
///
/// This function does no argument checking/validation.
///
/// Based on the glibc __clone3 implementation.
pub fn clone3() callconv(.Naked) usize {
    asm volatile (
        \\      mov      %%rcx, %%r8        // save args in preserved register
        \\
        \\      movl     $435, %%eax
        \\      .cfi_endproc
        \\      syscall
        \\
        \\      test     %%rax, %%rax
        \\      jz       _clone_start
        \\      retq
        \\
        \\
        \\ _clone_start:
        \\      .cfi_startproc
        \\      .cfi_undefined %%rip
        \\      xorl    %%ebp, %%ebp        // clear frame pointer
        \\
        \\      mov     %%r8, %%rdi
        \\      callq   *%%rdx
        \\      movl    %%eax, %%edi
        \\      movl    $60, %%eax          // SYS_exit
        \\      syscall
        \\
    );
}
