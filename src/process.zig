const std = @import("std");

const posix = std.posix;
const linux = std.os.linux;

pub const Process = struct {
    id: linux.pid_t,
    fd: linux.fd_t,

    const SpawnFileAction = union(enum) {
        dup2: struct {
            old: linux.fd_t,
            new: linux.fd_t,
        },
        close: linux.fd_t,
    };

    const SpawnError = error{
        Unexpected,
    };

    pub fn spawn(
        gpa: std.mem.Allocator,
        arg_file: []const u8,
        file_actions: []const SpawnFileAction,
        arg_argv: []const []const u8,
        arg_envp: []const []const u8,
    ) (error{OutOfMemory} || SpawnError)!Process {
        var arena_state = std.heap.ArenaAllocator.init(gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();

        const file = (try arena.dupeZ(u8, arg_file)).ptr;

        const argv_buf = try arena.allocSentinel(?[*:0]const u8, arg_argv.len, null);
        for (argv_buf, arg_argv) |*dst, src| dst.* = (try arena.dupeZ(u8, src)).ptr;

        const envp_buf = try arena.allocSentinel(?[*:0]const u8, arg_envp.len, null);
        for (envp_buf, arg_envp) |*dst, src| dst.* = (try arena.dupeZ(u8, src)).ptr;

        return spawnImpl(file, file_actions, argv_buf.ptr, envp_buf.ptr);
    }

    fn spawnImpl(
        file: [*:0]const u8,
        file_actions: []const SpawnFileAction,
        argv: [*:null]const ?[*:0]const u8,
        envp: [*:null]const ?[*:0]const u8,
    ) SpawnError!Process {
        if (try fork()) |child| {
            // parent

            // TODO: error communication with child

            return .{ .id = child.id, .fd = child.fd };
        } else {
            //child

            for (file_actions) |fa| switch (fa) {
                // CLOEXEC is unset for the duplicate file descriptor.
                .dup2 => |args| posix.dup2(args.old, args.new) catch {},

                .close => |fd| posix.close(fd),
            };

            // TODO: error communication with parent

            posix.execvpeZ(file, argv, envp) catch {};
            unreachable;
        }
    }

    /// Terminates a process using a multi-step approach:
    /// 1. Checks if process has already ended
    /// 2. Sends SIGTERM and waits for the specified timeout
    /// 3. If process still running after timeout, sends SIGKILL
    /// The process handle is automatically closed after termination.
    ///
    /// Arguments:
    ///   p: Process handle to terminate
    ///   timeout_sigterm_ms: Milliseconds to wait after SIGTERM before sending SIGKILL
    pub fn terminate(p: Process, timeout_sigterm_ms: u31) void {
        // No matter what at the end of the function this handle must be closed.
        defer p.close();

        // Optimistically check if process is already ended.
        if ((p.wait(0) catch @panic("todo")) == null) return;

        // Ask nicely with SIGTERM.
        p.signal(posix.SIG.TERM) catch @panic("todo");
        if (p.wait(timeout_sigterm_ms) catch @panic("todo")) |_| return;

        // No longer asking.
        p.signal(posix.SIG.KILL) catch {};
        _ = p.wait(0) catch {};
    }

    /// Closes the process handle.
    /// This does not terminate the process, it only closes the file descriptor.
    pub fn close(p: Process) void {
        posix.close(p.fd);
    }

    /// Waits for the process to exit with a timeout.
    ///
    /// Arguments:
    ///   p: Process handle to wait for
    ///   arg_timeout_ms: Timeout in milliseconds. Use negative value for infinite wait,
    ///                   0 for immediate return, or positive value for timed wait.
    ///
    /// Returns:
    ///   null if the process has not exited within timeout period
    ///   siginfo_t struct containing process exit information if process has exited
    ///
    /// Errors:
    ///   TODO
    pub fn wait(p: Process, arg_timeout_ms: i32) !?linux.siginfo_t {
        const flag_nohang: u32 = blk: {
            // Infinite timeout.
            if (arg_timeout_ms < 0) break :blk 0;

            // Zero timeout.
            if (arg_timeout_ms == 0) break :blk linux.W.NOHANG;

            // Other timeout.
            var poll_fds = [_]posix.pollfd{.{ .fd = p.fd, .events = linux.POLL.IN, .revents = 0 }};
            if ((try posix.poll(&poll_fds, arg_timeout_ms)) == 0) return null;
            break :blk linux.W.NOHANG;
        };

        var siginfo: linux.siginfo_t = undefined;
        while (true) {
            switch (linux.E.init(linux.waitid(
                linux.P.PIDFD,
                p.fd,
                &siginfo,
                linux.W.EXITED | flag_nohang,
            ))) {
                .SUCCESS => break,
                .INTR => continue,
                .CHILD => unreachable, // The process specified does not exist. It would be a race condition to handle this error.
                .INVAL => unreachable, // Invalid flags.
                else => |e| return posix.unexpectedErrno(e),
            }
        }

        // If WNOHANG is specified and the status is not available,
        // waitid returns zero and sets si_signo and si_pid in
        // siginfo to zero.
        return if (siginfo.signo != 0) siginfo else null;
    }

    /// Sends a signal to the process.
    ///
    /// Arguments:
    ///   p: Process handle to signal
    ///   sig: Signal number to send (e.g. SIGTERM, SIGKILL)
    ///
    /// Errors:
    ///   error.PermissionDenied - Insufficient permissions to signal the process
    ///   error.ProcessNotFound - Process no longer exists
    ///   Unexpected system errors
    pub fn signal(p: Process, sig: i32) !void {
        switch (linux.E.init(linux.pidfd_send_signal(p.fd, sig, null, 0))) {
            .SUCCESS => return,
            .BADF, .INVAL => unreachable,
            .PERM => return error.PermissionDenied,
            .SRCH => return error.ProcessNotFound,
            else => |err| return posix.unexpectedErrno(err),
        }
    }

    /// Creates a duplicate handle for the process.
    /// The new handle must be closed separately.
    ///
    /// Arguments:
    ///   p: Process handle to duplicate
    ///
    /// Returns:
    ///   A new Process handle referring to the same process
    ///
    /// Errors:
    ///   error.ProcessFdQuotaExceeded - Exceeded system resource limit
    ///   Unexpected system errors
    pub fn dup(p: Process) !Process {
        return .{ .id = p.id, .fd = try posix.dup(p.fd) };
    }
};

fn fork() !?struct { id: linux.pid_t, fd: linux.fd_t } {
    const clone_args = extern struct {
        flags: u64,

        // *linux.fd_t
        pidfd: u64,

        // *linux.pid_t
        child_tid: u64,

        // *linux.pid_t
        parent_tid: u64,

        exit_signal: u64,

        // ?*[*]u8
        stack: u64,

        stack_size: u64,

        // (?)
        tls: u64,
    };

    var fd: linux.fd_t = undefined;

    var args = clone_args{
        .flags = linux.CLONE.PIDFD,
        .pidfd = @intFromPtr(&fd),
        .child_tid = 0,
        .parent_tid = 0,
        .exit_signal = linux.SIG.CHLD,
        .stack = 0,
        .stack_size = 0,
        .tls = 0,
    };

    const rc = linux.syscall2(linux.SYS.clone3, @intFromPtr(&args), @sizeOf(@TypeOf(args)));
    return switch (linux.E.init(rc)) {
        .SUCCESS => if (rc != 0) .{ .id = @intCast(rc), .fd = fd } else null,
        else => |e| posix.unexpectedErrno(e),
    };
}
