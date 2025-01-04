const builtin = @import("builtin");
const std = @import("std");
const assert = std.debug.assert;
const print = std.debug.print;

const posix = std.posix;
const linux = std.os.linux;

const arch_bits = switch (builtin.cpu.arch) {
    .x86_64 => @import("arch/x86_64.zig"),
    else => @compileError("unsupported architecture"),
};

const log = std.log;

pub fn main() !void {
    var gpa_state = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa_state.deinit();
    const gpa = gpa_state.allocator();

    const proc = try Process.spawn(gpa, "ls", &.{}, &.{ "ls", "-lh", "/proc/self/fd" }, &.{});
    log.info("child pid: {d}", .{proc.pid});
    // try proc.signal(linux.SIG.TERM);
    _ = try proc.wait(0);
}

const Process = struct {
    pid: linux.pid_t,
    pid_fd: linux.fd_t,

    const SpawnFileActions = union(enum) {
        open: struct {
            new: linux.fd_t,
            path: []const u8,
            flags: linux.O,
            mode: linux.mode_t,
        },
        dup2: struct {
            old: linux.fd_t,
            new: linux.fd_t,
        },
        close: linux.fd_t,
    };

    pub const SpawnError = error{
        /// Specified path is too long.
        NameTooLong,
    };

    pub fn spawn(
        gpa: std.mem.Allocator,
        arg_file: []const u8,
        file_actions: []const SpawnFileActions,
        arg_argv: []const []const u8,
        arg_envp: []const []const u8,
    ) !Process {
        _ = file_actions; // autofix
        var arena_state = std.heap.ArenaAllocator.init(gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();

        const file = try posix.toPosixPath(arg_file);

        // The POSIX standard does not allow malloc() between fork() and execve(),
        // and `gpa` may be a libc allocator.
        // Additionally, we want to reduce the number of possible ways things
        // can fail between fork() and execve().
        // Therefore, we do all the allocation for the execve() before the fork().
        // This means we must do the null-termination of argv and env vars here.
        const argv = try arena.allocSentinel(?[*:0]const u8, arg_argv.len, null);
        for (arg_argv, 0..) |arg, i| argv[i] = (try arena.dupeZ(u8, arg)).ptr;

        const envp = try arena.allocSentinel(?[*:0]const u8, arg_envp.len, null);
        for (arg_envp, 0..) |env, i| envp[i] = (try arena.dupeZ(u8, env)).ptr;

        // TODO: set up communication between parent and child

        // pid_fd is created with FD_CLOEXEC (own testing).
        var pid_fd: linux.fd_t = undefined;
        var cl_args: clone_args = .{
            .flags = linux.CLONE.PIDFD,
            .pidfd = &pid_fd,
            .child_tid = null,
            .parent_tid = null,
            .exit_signal = linux.SIG.CHLD,
            .stack = null,
            .stack_size = 0,
            .tls = 0,
        };

        const child_args = ChildArgs{
            .pid_fd = &pid_fd,
            .path = &file,
            .argv = argv.ptr,
            .envp = envp.ptr,
        };

        const rc = clone3(&cl_args, child, @intFromPtr(&child_args));
        switch (errno(rc)) {
            .SUCCESS => {},
            else => |e| {
                _ = e; // autofix
                @panic("TODO: error handling on clone");
            },
        }

        // This is the parent.

        const pid: linux.pid_t = @intCast(rc);

        // TODO: receive errors from child

        return Process{ .pid = pid, .pid_fd = pid_fd };
    }

    const ChildArgs = struct {
        pid_fd: *linux.fd_t,
        path: [*:0]const u8,
        argv: [*:null]?[*:0]const u8,
        envp: [*:null]?[*:0]const u8,
    };

    fn child(args: usize) callconv(.C) u8 {
        const child_args: *const ChildArgs = @ptrFromInt(args);

        const e = posix.execvpeZ_expandArg0(
            .expand,
            child_args.path,
            child_args.argv,
            child_args.envp,
        );
        e catch {};
        return 1;
    }

    pub fn signal(proc: Process, sig: i32) !void {
        switch (errno(linux.pidfd_send_signal(proc.pid_fd, sig, null, 0))) {
            .SUCCESS => return,
            .BADF => unreachable,
            .INVAL => unreachable,
            .PERM => return error.PermissionDenied,
            .SRCH => return error.ProcessNotFound,
            else => |err| return posix.unexpectedErrno(err),
        }
    }

    pub fn wait(proc: Process, arg_timeout_ms: i32) !?linux.siginfo_t {
        const flag_nohang: u32 = blk: {
            // Infinite timeout.
            if (arg_timeout_ms < 0) break :blk 0;

            // Zero timeout.
            if (arg_timeout_ms == 0) break :blk linux.W.NOHANG;

            // Other timeout.
            var poll_fds = [_]posix.pollfd{.{ .fd = proc.pid_fd, .events = linux.POLL.IN, .revents = 0 }};
            if ((try posix.poll(&poll_fds, arg_timeout_ms)) == 0) return null;
            break :blk linux.W.NOHANG;
        };

        var timeout_ms = arg_timeout_ms;
        var t_start: std.time.Instant = if (timeout_ms > 0) (std.time.Instant.now() catch unreachable) else undefined;
        var siginfo: linux.siginfo_t = undefined;
        loop: while (true) {
            switch (errno(linux.waitid(
                linux.P.PIDFD,
                proc.pid_fd,
                &siginfo,
                linux.W.EXITED | flag_nohang,
            ))) {
                .SUCCESS => break :loop,
                .INTR => {
                    if (timeout_ms > 0) {
                        const t_now = std.time.Instant.now() catch unreachable;
                        timeout_ms -= @intCast(t_now.since(t_start) / std.time.ns_per_ms);
                        t_start = t_now;
                    }
                    continue;
                },
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
};

fn errno(rc: anytype) linux.E {
    const signed: isize = @bitCast(rc);
    const int = if (signed > -4096 and signed < 0) -signed else 0;
    return @enumFromInt(int);
}

const clone_args = extern struct {
    flags: u64,
    pidfd: ?*linux.fd_t,
    child_tid: ?*linux.pid_t,
    parent_tid: ?*linux.pid_t,
    exit_signal: u64,
    stack: ?[*]u8,
    stack_size: u64,
    tls: u64,
};

const clone_args1 = Extend(clone_args, extern struct {
    set_tid: [*]linux.pid_t,
    set_tid_size: u64,
});

const clone_args2 = Extend(clone_args1, extern struct {
    cgroup: u64,
});

const CloneFn = fn (args: usize) callconv(.C) u8;

fn clone3(cl_args: anytype, func: *const CloneFn, args: usize) usize {
    const CloneArgs = switch (@TypeOf(cl_args)) {
        *clone_args,
        *clone_args1,
        *clone_args2,
        => @typeInfo(@TypeOf(cl_args)).Pointer.child,
        else => @compileError("cl_args must be a non-const pointer to a clone_args type"),
    };

    const impl = @as(*const fn (
        *CloneArgs,
        usize,
        *const CloneFn,
        usize,
    ) usize, @ptrCast(&arch_bits.clone3));

    return impl(cl_args, @sizeOf(CloneArgs), func, args);
}

fn Extend(comptime T: type, comptime ExtraFields: type) type {
    const type_info = @typeInfo(T);
    if (type_info != .Struct and type_info.Struct.layout != .@"extern") @compileError("provided T type must be an extern struct");

    const type_info_extra = @typeInfo(ExtraFields);
    if (type_info_extra != .Struct and type_info_extra.Struct.layout != .@"extern") @compileError("provided ExtraFields type must be an extern struct");

    const fields_len = type_info.Struct.fields.len + type_info_extra.Struct.fields.len;
    var fields: [fields_len]std.builtin.Type.StructField = undefined;

    var i: usize = 0;
    for (type_info.Struct.fields) |f| {
        fields[i] = f;
        i += 1;
    }
    for (type_info_extra.Struct.fields) |f| {
        fields[i] = f;
        i += 1;
    }

    var type_info_new = type_info;
    type_info_new.Struct.fields = &fields;
    type_info_new.Struct.decls = &.{};

    return @Type(type_info_new);
}
