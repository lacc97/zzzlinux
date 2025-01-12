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

    const proc = try Process.spawn(
        gpa,
        "true",
        &.{},
        &.{"true"},
        &.{},
    );
    defer {
        const exit_info = proc.terminate(100);
        log.info("exited with {any}", .{exit_info});
    }

    log.info("child pid: {d}", .{proc.id});
    std.time.sleep(100 * std.time.ns_per_ms);
}
