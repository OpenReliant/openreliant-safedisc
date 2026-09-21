//! `safedisc`: recovers StarLancer's game executable from its SafeDisc 1 wrapper, for the
//! OpenReliant analysis, which reads it from `game/decrypted/LANCER.EXE`. `docs/safedisc.md`
//! describes the scheme.

const std = @import("std");
const Io = std.Io;

const Command = @import("command.zig").Command;

/// What every command needs to do its work.
pub const Context = struct {
    io: Io,
    arena: std.mem.Allocator,
    stdout: *Io.Writer,
};

const usage =
    \\usage: safedisc <command> ...
    \\
    \\commands:
    \\
++ Command.usage;

pub fn main(init: std.process.Init) !u8 {
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);

    // Streaming, not positional: stdout may be a file that other processes also append to.
    var stdout_buffer: [4096]u8 = undefined;
    var stdout: Io.File.Writer = .initStreaming(.stdout(), init.io, &stdout_buffer);

    const command = Command.parse(args[1..]) catch {
        std.debug.print("{s}", .{usage});
        return 2;
    };
    run(command, init, arena, &stdout) catch |err| switch (err) {
        // The reader went away, as `safedisc ... | head` does: stop quietly, not with a trace.
        error.WriteFailed => {
            const cause = stdout.err orelse return err;
            return if (cause == error.BrokenPipe) 0 else err;
        },
        else => return err,
    };
    return 0;
}

fn run(command: Command, init: std.process.Init, arena: std.mem.Allocator, stdout: *Io.File.Writer) !void {
    try command.run(.{ .io = init.io, .arena = arena, .stdout = &stdout.interface });
    try stdout.interface.flush();
}

test {
    std.testing.refAllDecls(@This());
    _ = @import("command.zig");
    _ = @import("pe.zig");
    _ = @import("safedisc.zig");
    _ = @import("tea.zig");
}
