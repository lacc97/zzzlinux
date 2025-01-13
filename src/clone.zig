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

const Process = @import("process.zig").Process;

pub fn main() !void {
    var gpa_state = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa_state.deinit();
    const gpa = gpa_state.allocator();

    var procs = std.ArrayListUnmanaged(Process){};
    defer procs.deinit(gpa);
    defer Process.terminateAll(gpa, procs.items, null, 100) catch unreachable;

    for (0..10) |_| {
        try procs.append(gpa, try Process.spawn(
            gpa,
            "sleep",
            &.{},
            &.{ "sleep", "10" },
            &.{},
        ));
    }

    const proc = try Process.spawn(
        gpa,
        "true",
        &.{},
        &.{"true"},
        &.{},
    );
    defer {
        const exit_info1 = proc.terminate(100);
        log.info("exited with {any}", .{exit_info1});
    }

    log.info("child pid: {d}", .{proc.id});
    const exit_info2 = try proc.waitForExit(.{ .timeout_ms = -1 }) orelse unreachable;
    log.info("waited for exit with {any}", .{exit_info2});
}
