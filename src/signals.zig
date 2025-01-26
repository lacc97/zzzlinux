const std = @import("std");

const posix = std.posix;
const linux = std.os.linux;

/// Type alias for POSIX signal set type.
pub const SigSet = posix.sigset_t;

/// Options for controlling signal blocking behaviour.
pub const BlockOptions = struct {
    /// Also block signals which if generated while blocked produce
    /// undefined results (SIGBUS, SIGFPE, SIGILL, SIGSEGV).
    all: bool = false,
};

/// Blocks signals in the current thread and returns the previous signal mask.
///
/// This function blocks most signals except for those that would result in undefined
/// behaviour when blocked (SIGBUS, SIGFPE, SIGILL, SIGSEGV). These signals
/// can be optionally blocked by setting opts.all to true.
///
/// Arguments:
///   opts: BlockOptions controlling which signals to block
///
/// Returns:
///   Previous signal mask that can be used to restore the original signal state.
pub fn block(opts: BlockOptions) SigSet {
    const new_mask: SigSet = blk: {
        var mask = posix.filled_sigset;
        if (!opts.all) {
            sigdelset(&mask, posix.SIG.BUS);
            sigdelset(&mask, posix.SIG.FPE);
            sigdelset(&mask, posix.SIG.ILL);
            sigdelset(&mask, posix.SIG.SEGV);
        }
        break :blk mask;
    };

    var old_mask: SigSet = undefined;
    posix.sigprocmask(posix.SIG.SETMASK, &new_mask, &old_mask);
    return old_mask;
}

/// Restores the signal mask to a previously saved state.
///
/// This function is typically used to restore signal handling after a previous
/// call to block().
///
/// Arguments:
///   old_mask: Signal mask previously returned by block()
pub fn unblock(old_mask: SigSet) void {
    posix.sigprocmask(posix.SIG.SETMASK, &old_mask, null);
}

fn sigdelset(set: *linux.sigset_t, sig: u6) void {
    const s = sig - 1;
    // shift in musl: s&8*sizeof *set->__bits-1
    const shift = @as(u5, @intCast(s & (usize_bits - 1)));
    const val = @as(u32, @intCast(1)) << shift;
    (set.*)[@as(usize, @intCast(s)) / usize_bits] &= ~val;
}

const usize_bits = @typeInfo(usize).Int.bits;
