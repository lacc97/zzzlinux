const std = @import("std");
const assert = std.debug.assert;

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

    const SpawnError = posix.UnexpectedError || posix.ForkError || posix.ExecveError || error{
        SystemFdQuotaExceeded,
        ProcessFdQuotaExceeded,
    };

    const ChildError = union(enum) {
        exec: SpawnError,
        file_action: struct {
            idx: usize,
            err: SpawnError,
        },
    };

    /// Creates a new process by executing the specified program.
    ///
    /// This function creates a new process using Linux's clone3 system call and executes
    /// the specified program in the child process. It provides functionality for file
    /// descriptor manipulation in the child process before program execution.
    ///
    /// Arguments:
    ///   gpa: General purpose allocator used for temporary allocations during process setup
    ///   arg_file: Path to the executable file to run
    ///   file_actions: Array of file descriptor operations to perform in the child process
    ///                 before executing the new program. Supports:
    ///                 - dup2: Duplicate a file descriptor to a new number
    ///                 - close: Close a file descriptor
    ///   arg_argv: Array of command-line arguments for the new program
    ///   arg_envp: Array of environment variables for the new program
    ///
    /// Returns:
    ///   On success: Process struct containing:
    ///     - id: Process ID of the new process
    ///     - fd: File descriptor for process management (pidfd)
    ///
    /// Errors:
    ///   error.OutOfMemory: Failed to allocate memory for process setup
    ///   error.SystemResources: System resource limits reached (memory, processes, etc.)
    ///   error.SystemFdQuotaExceeded: System-wide file descriptor limit reached
    ///   error.ProcessFdQuotaExceeded: Process-specific file descriptor limit reached
    ///   posix.UnexpectedError: Other system-level errors
    ///   posix.ForkError: Failed to create new process
    ///   posix.ExecveError: Failed to execute the new program
    ///
    /// Notes:
    /// - Uses an ArenaAllocator internally for temporary allocations
    /// - All strings are converted to null-terminated format required by POSIX
    /// - File actions are performed in order specified
    /// - Provides detailed error reporting from child process via pipe
    /// - Uses modern Linux features (clone3, pidfd) for robust process management
    /// - Child process errors are communicated back to parent through ChildError union
    ///
    /// Example:
    /// ```zig
    /// const actions = [_]Process.SpawnFileAction{
    ///     .{ .dup2 = .{ .old = stdout_pipe, .new = STDOUT_FILENO } },
    ///     .{ .close = stderr_fd },
    /// };
    /// const process = try Process.spawn(
    ///     allocator,
    ///     "/usr/bin/ls",
    ///     &actions,
    ///     &.{"/usr/bin/ls", "-l"},
    ///     &.{"PATH=/usr/bin"},
    /// );
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
        argv: [*:null]?[*:0]const u8,
        envp: [*:null]const ?[*:0]const u8,
    ) SpawnError!Process {
        // Create error communication pipes.
        const pipe_read, const pipe_write = blk: {
            const pipe_fds = try posix.pipe2(.{ .CLOEXEC = true });
            break :blk .{ pipe_fds[0], pipe_fds[1] };
        };

        const is_parent = fork() catch |e| {
            posix.close(pipe_write);
            posix.close(pipe_read);
            return e;
        };

        if (is_parent) |child| {
            const p = Process{ .id = child.id, .fd = child.fd };
            errdefer _ = p.terminate(0);

            posix.close(pipe_write);
            defer posix.close(pipe_read);

            // Read potential error from child
            var child_err: ChildError = undefined;
            if (posix.read(pipe_read, std.mem.asBytes(&child_err))) |bytes_read| {
                switch (bytes_read) {
                    // Clean EOF.
                    0 => return p,

                    // Child process reported an error.
                    @sizeOf(ChildError) => return switch (child_err) {
                        .exec => |e| e,
                        .file_action => |fa| fa.err,
                    },

                    else => unreachable,
                }
            } else |e| {
                std.debug.panic("{s}", .{@errorName(e)});
            }
        } else {
            // We never break from this block (we must terminate either through exec or exit).
            defer comptime unreachable;

            posix.close(pipe_read);

            // Helper to report errors back to parent
            const err = struct {
                fn err(fd: posix.fd_t, e: ChildError) noreturn {
                    _ = posix.write(fd, std.mem.asBytes(&e)) catch {};
                    linux.exit(1);
                }
            }.err;

            // Perform file actions
            for (file_actions, 0..) |fa, i| switch (fa) {
                .dup2 => |args| posix.dup2(args.old, args.new) catch |e| err(pipe_write, .{ .file_action = .{ .idx = i, .err = e } }),
                .close => |fd| posix.close(fd),
            };

            // Execute the new program
            const e = posix.execvpeZ_expandArg0(.expand, file, argv, envp);
            err(pipe_write, .{ .exec = e });
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
    pub fn terminate(p: Process, timeout_sigterm_ms: u31) ExitInfo {
        // No matter what at the end of the function this handle must be closed.
        defer p.close();

        const reap = struct {
            inline fn reap(arg_p: Process, timeout_ms: i32) !?ExitInfo {
                return arg_p.waitForExit(.{ .timeout_ms = timeout_ms, .reap = true });
            }
        }.reap;

        // Optimistically check if process is already ended.
        if ((reap(p, 0) catch |e| switch (e) {
            // Child process has already been reaped.
            error.ProcessNotFound => return .unknown,

            else => return .unknown,
        })) |exit_info| return exit_info;

        // Ask nicely with SIGTERM.
        p.signal(posix.SIG.TERM) catch |e| switch (e) {
            // This should not be possible because the previous
            // call to wait indicated we still have process
            // around. It might indicate a race condition.
            error.ProcessNotFound => return .unknown,
            else => return .unknown,
        };
        if (reap(p, timeout_sigterm_ms) catch |e| switch (e) {
            // This should not be possible because the previous
            // call to wait indicated we still have process
            // around. It might indicate a race condition.
            error.ProcessNotFound => .unknown,
            else => .unknown,
        }) |exit_info| return exit_info;

        // No longer asking.
        p.signal(posix.SIG.KILL) catch {};
        if (reap(p, 1) catch |e| switch (e) {
            // This should not be possible because the previous
            // call to wait indicated we still have process
            // around. It might indicate a race condition.
            error.ProcessNotFound => .unknown,
            else => .unknown,
        }) |exit_info| return exit_info;
        return .unknown;
    }

    /// Closes the process handle.
    /// This does not terminate the process, it only closes the file descriptor.
    pub fn close(p: Process) void {
        posix.close(p.fd);
    }

    pub const ExitInfo = union(enum) {
        exited: i32,
        signal: i32,
        unknown,
    };

    pub const WaitForExitOptions = struct {
        timeout_ms: i32,
        reap_child: bool = false,
    };

    /// Waits for the process to exit with a timeout.
    ///
    /// Arguments:
    ///   p: Process handle to wait for
    ///   opts: WaitForExitOptions struct containing:
    ///     - timeout_ms: Timeout in milliseconds. Use negative value for infinite wait,
    ///                   0 for immediate return, or positive value for timed wait
    ///     - reap_child: If true, reaps the child process. If false, leaves the process
    ///                   in a waitable state (using WNOWAIT)
    ///
    /// Returns:
    ///   null if the process has not exited within timeout period
    ///   ExitInfo union containing either:
    ///     - exited: Normal process exit with status code
    ///     - signal: Process terminated by signal
    ///     - unknown: Process state could not be determined
    ///
    /// Errors:
    ///   error.ProcessNotFound: Process no longer exists or has already been reaped
    ///   posix.UnexpectedError: Other system-level errors
    pub fn waitForExit(p: Process, opts: WaitForExitOptions) !?ExitInfo {
        const flag_nohang: u32 = blk: {
            // Infinite timeout.
            if (opts.timeout_ms < 0) break :blk 0;

            // Zero timeout.
            if (opts.timeout_ms == 0) break :blk linux.W.NOHANG;

            // Other timeout.
            var poll_fds = [_]posix.pollfd{.{ .fd = p.fd, .events = linux.POLL.IN, .revents = 0 }};
            const ready = posix.poll(&poll_fds, opts.timeout_ms) catch |e| switch (e) {
                error.NetworkSubsystemFailed => unreachable, // not using the network
                else => |e0| return e0,
            };
            if (ready == 0) return null;
            break :blk linux.W.NOHANG;
        };

        const flag_nowait: u32 = if (!opts.reap_child) linux.W.NOWAIT else 0;

        if (try waitid(
            linux.P.PIDFD,
            p.fd,
            // We set NOWAIT so we can always retrieve the status
            // again (especially during terminate()).
            linux.W.EXITED | flag_nowait | flag_nohang,
        )) |wait_info| {
            assert(p.id == wait_info.pid);
            return switch (wait_info.code) {
                .EXITED => .{ .exited = wait_info.status },
                .KILLED, .DUMPED => .{ .signal = wait_info.status },
                .STOPPED, .TRAPPED, .CONTINUED => unreachable,
            };
        } else {
            return null;
        }
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

fn fork() posix.ForkError!?struct { id: linux.pid_t, fd: linux.fd_t } {
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
        .AGAIN => return error.SystemResources,
        .NOMEM => return error.SystemResources,
        else => |e| posix.unexpectedErrno(e),
    };
}

const WaitInfo = struct {
    code: CLD,
    pid: linux.pid_t,
    uid: linux.uid_t,
    status: i32,
};

const CLD = enum(i32) {
    // child has exited
    EXITED = 1,
    // child was killed
    KILLED = 2,
    // child terminated abnormally
    DUMPED = 3,
    // traced child has trapped
    TRAPPED = 4,
    // child has stopped
    STOPPED = 5,
    // stopped child has continued
    CONTINUED = 6,
};

fn waitid(id_type: linux.P, id: i32, options: u32) !?WaitInfo {
    var siginfo: linux.siginfo_t = undefined;

    // wait(2) manpage suggests setting si_pid to 0 and checking for
    // a non-zero value after the call returns to distinguish between
    // successfully waiting for a child vs passing WNOHANG with
    // no waitable children.
    siginfo.fields.common.first.piduid.pid = 0;

    while (true) switch (linux.E.init(linux.waitid(
        id_type,
        id,
        &siginfo,
        options,
    ))) {
        .SUCCESS => break,
        .AGAIN => return null,
        .INTR => continue,
        .CHILD => return error.ProcessNotFound,
        .INVAL => unreachable, // Invalid flags.
        else => |e| return posix.unexpectedErrno(e),
    };

    if (siginfo.fields.common.first.piduid.pid == 0) {
        // See above comment.
        return null;
    }

    return .{
        .code = @enumFromInt(siginfo.code),
        .pid = siginfo.fields.common.first.piduid.pid,
        .uid = siginfo.fields.common.first.piduid.uid,
        .status = siginfo.fields.common.second.sigchld.status,
    };
}
