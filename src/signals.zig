const std = @import("std");
const panic = std.debug.panic;

const posix = std.posix;
const linux = std.os.linux;

/// Type alias for POSIX signal set type.
pub const SigSet = posix.sigset_t;

const TerminationState = struct {
    pipes: [2]posix.fd_t,
    old_actions: [signals.len]posix.Sigaction,

    const signals = [_]u6{ posix.SIG.INT, posix.SIG.TERM };
};

var termination_state: ?TerminationState = null;

pub fn installTerminationHandler() !posix.fd_t {
    if (termination_state != null) panic("termination handler is already installed", .{});

    termination_state = @as(TerminationState, undefined);
    errdefer termination_state = null;

    const state: *TerminationState = &termination_state.?;

    state.pipes = try posix.pipe2(.{ .CLOEXEC = true, .NONBLOCK = true });
    errdefer {
        posix.close(state.pipes[0]);
        posix.close(state.pipes[1]);
    }

    const new_action: posix.Sigaction = .{
        .handler = .{ .handler = terminationHandler },
        .mask = mask_blk: {
            var mask: SigSet = posix.empty_sigset;
            inline for (TerminationState.signals) |sig| sigaddset(&mask, sig);
            break :mask_blk mask;
        },
        .flags = 0,
    };
    inline for (TerminationState.signals, &state.old_actions) |sig, *old_action| {
        posix.sigaction(sig, &new_action, old_action) catch unreachable;
    }
    errdefer for (TerminationState.signals, &state.old_actions) |sig, *old_action| {
        posix.sigaction(sig, old_action, null) catch unreachable;
    };

    return state.pipes[0];
}

pub fn uninstallTerminationHandler() void {
    if (termination_state == null) panic("termination handler is not installed", .{});

    const state: *TerminationState = &termination_state.?;

    for (TerminationState.signals, &state.old_actions) |sig, *old_action| {
        posix.sigaction(sig, old_action, null) catch unreachable;
    }

    posix.close(state.pipes[0]);
    posix.close(state.pipes[1]);

    termination_state = null;
}

fn terminationHandler(sig: i32) callconv(.C) void {
    _ = sig; // autofix
    if (termination_state) |*state| {
        const cookie: u8 = 1;
        _ = posix.write(state.pipes[1], std.mem.asBytes(&cookie)) catch {};
    }
}

test "termination signal handler" {
    const testing = std.testing;

    for (TerminationState.signals) |sig| {
        const pipe = try installTerminationHandler();
        defer uninstallTerminationHandler();

        var buf: [256]u8 = undefined;

        try testing.expectError(error.WouldBlock, posix.read(pipe, &buf));

        try posix.raise(sig);

        try testing.expectEqual(@as(usize, 1), try posix.read(pipe, &buf));
        try testing.expectEqual(@as(u8, 1), buf[0]);
    }
}

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

test "signal blocking and unblocking" {
    const testing = std.testing;

    const old_set = block(.{});
    errdefer unblock(old_set);

    const pipe = try installTerminationHandler();
    defer uninstallTerminationHandler();

    var buf: [256]u8 = undefined;

    for (TerminationState.signals) |sig| try posix.raise(sig);

    try testing.expectError(error.WouldBlock, posix.read(pipe, &buf));

    unblock(old_set);

    try testing.expectEqual(@as(usize, 2), try posix.read(pipe, &buf));
    try testing.expectEqual(@as(u8, 1), buf[0]);
    try testing.expectEqual(@as(u8, 1), buf[1]);
}

const sigaddset = linux.sigaddset;

fn sigdelset(set: *linux.sigset_t, sig: u6) void {
    const s = sig - 1;
    // shift in musl: s&8*sizeof *set->__bits-1
    const shift = @as(u5, @intCast(s & (usize_bits - 1)));
    const val = @as(u32, @intCast(1)) << shift;
    (set.*)[@as(usize, @intCast(s)) / usize_bits] &= ~val;
}

const usize_bits = @typeInfo(usize).Int.bits;
