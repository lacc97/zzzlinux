const std = @import("std");
const assert = std.debug.assert;
const print = std.debug.print;

const linux = std.os.linux;

const log = std.log;

pub fn main() u8 {
    var gpa_state = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa_state.deinit();
    const gpa = gpa_state.allocator();
    _ = gpa; // autofix

    var pidfd: linux.fd_t = undefined;

    var cl_args: clone_args = .{
        .flags = linux.CLONE.PIDFD | linux.CLONE.VFORK,
        .pidfd = &pidfd,
        .child_tid = null,
        .parent_tid = null,
        .exit_signal = linux.SIG.CHLD,
        .stack = null,
        .stack_size = 0,
        .tls = 0,
    };

    const rc = clone3(&cl_args);
    switch (errno(rc)) {
        .SUCCESS => {},
        else => |e| {
            log.err("clone3: {s}", .{@tagName(e)});
            return 1;
        },
    }
    if (rc == 0) {
        print("child\n", .{});
    } else {
        print("parent (child with pid {d})\n", .{rc});
    }

    print("rc:{d} pidfd:{d}\n", .{ rc, pidfd });
    return 0;
}

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

fn clone3(cl_args: anytype) isize {
    const size = switch (@TypeOf(cl_args)) {
        *clone_args,
        *clone_args1,
        *clone_args2,
        => @sizeOf(@typeInfo(@TypeOf(cl_args)).Pointer.child),
        else => @compileError("cl_args must be a non-const pointer to a clone_args type"),
    };

    return @bitCast(linux.syscall2(linux.SYS.clone3, @intFromPtr(cl_args), size));
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
