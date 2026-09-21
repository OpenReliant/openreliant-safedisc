//! The commands: inspect and decrypt a SafeDisc 1 payload (`LANCER.ICD`).

const std = @import("std");
const Io = std.Io;

const pe = @import("pe.zig");
const safedisc = @import("safedisc.zig");
const tea = @import("tea.zig");

const Context = @import("main.zig").Context;

pub const Command = union(enum) {
    info: struct { image: []const u8 },
    /// Recovers the key by brute force and prints it.
    key: struct { image: []const u8 },
    /// Writes a decrypted copy. The key is recovered unless `--key` gives one.
    decrypt: struct { image: []const u8, out: []const u8, key: ?u32 = null },
    /// Lists the import tables SafeDisc emptied, as recovered from the file.
    imports: struct { image: []const u8, key: ?u32 = null },

    pub const usage =
        \\  safedisc info <icd>             report sections, encryption and import state
        \\  safedisc key <icd>              recover the TEA key (searches 2^32 keys)
        \\  safedisc decrypt <icd> <out> [--key <hex>]
        \\                                  write a decrypted copy of the payload
        \\  safedisc imports <icd> [--key <hex>]
        \\                                  recover the API names from the emptied tables
        \\
    ;

    pub fn parse(args: []const [:0]const u8) error{Usage}!Command {
        if (args.len == 0) return error.Usage;
        const verb = std.meta.stringToEnum(std.meta.Tag(Command), args[0]) orelse return error.Usage;
        const operands = args[1..];
        switch (verb) {
            .info => return if (operands.len == 1) .{ .info = .{ .image = operands[0] } } else error.Usage,
            .key => return if (operands.len == 1) .{ .key = .{ .image = operands[0] } } else error.Usage,
            .imports => {
                if (operands.len != 1 and operands.len != 3) return error.Usage;
                var command: Command = .{ .imports = .{ .image = operands[0] } };
                if (operands.len == 3) command.imports.key = try parseKeyOption(operands[1..]);
                return command;
            },
            .decrypt => {
                if (operands.len != 2 and operands.len != 4) return error.Usage;
                var command: Command = .{ .decrypt = .{ .image = operands[0], .out = operands[1] } };
                if (operands.len == 4) command.decrypt.key = try parseKeyOption(operands[2..]);
                return command;
            },
        }
    }

    fn parseKeyOption(args: []const [:0]const u8) error{Usage}!u32 {
        if (!std.mem.eql(u8, args[0], "--key")) return error.Usage;
        const text = args[1];
        const digits = if (std.ascii.startsWithIgnoreCase(text, "0x")) text[2..] else text;
        return std.fmt.parseInt(u32, digits, 16) catch error.Usage;
    }

    pub fn run(command: Command, ctx: Context) !void {
        const path = switch (command) {
            inline else => |operands| operands.image,
        };
        const bytes = try Io.Dir.cwd().readFileAlloc(ctx.io, path, ctx.arena, .limited(64 << 20));
        const image: pe.Image = try .parse(bytes);

        switch (command) {
            .info => try info(ctx, image),
            .key => {
                const recovery = try recover(ctx, image);
                try ctx.stdout.print("key: {x:0>8} (repeated 4x)\n", .{recovery.key.words[0]});
            },
            .decrypt => |operands| {
                const key: tea.Key = if (operands.key) |word|
                    .repeated(word)
                else
                    (try recover(ctx, image)).key;

                const report = try safedisc.decrypt(ctx.arena, image, key);
                if (report.len == 0) return error.NothingToDecrypt;
                for (report) |section| {
                    try ctx.stdout.print(
                        "  {s:<8} entropy {d:.2} -> {d:.2}\n",
                        .{ section.name, section.entropy_before, section.entropy_after },
                    );
                }

                try Io.Dir.cwd().writeFile(ctx.io, .{ .sub_path = operands.out, .data = bytes });
                try ctx.stdout.print("wrote {s} ({Bi:.1})\n", .{ operands.out, bytes.len });
            },
            .imports => |operands| {
                const key: tea.Key = if (operands.key) |word|
                    .repeated(word)
                else
                    (try recover(ctx, image)).key;

                const recovery = try safedisc.imports.recover(ctx.arena, image, key);
                try ctx.stdout.print("name encryption seed: {x:0>2}\n", .{recovery.seed});
                for (recovery.libraries) |library| {
                    try ctx.stdout.print("\n{s}: {d} API names\n", .{ library.name, library.entries.len });
                    for (library.entries) |entry| {
                        try ctx.stdout.print("  {x:0>6}  {s}{s}\n", .{
                            entry.name.rva,
                            entry.name.text,
                            if (entry.restored) "   (entry was unreferenced; its thunk was zeroed)" else "",
                        });
                    }
                }
                try ctx.stdout.writeAll(
                    \\
                    \\These are the names the two tables import, which is certain. Their order in the
                    \\table is not: SafeDisc shuffles the thunks, so a table slot does not name the API
                    \\the code calls through it. See docs/safedisc.md.
                    \\
                );
            },
        }
    }
};

fn recover(ctx: Context, image: pe.Image) !safedisc.KeyRecovery {
    const threads = std.Thread.getCpuCount() catch 1;
    try ctx.stdout.print("searching 2^32 keys on {d} threads...\n", .{threads});
    try ctx.stdout.flush();
    return safedisc.recoverKey(ctx.arena, image, threads);
}

fn info(ctx: Context, image: pe.Image) !void {
    const optional = image.optional_header;
    try ctx.stdout.print(
        \\machine:     {t}
        \\image base:  {x:0>8}
        \\entry point: {x:0>8}
        \\linker:      {d}.{d}
        \\
        \\sections:
        \\
    , .{
        image.file_header.machine,
        optional.image_base,
        optional.image_base + optional.entry_point,
        optional.linker_major,
        optional.linker_minor,
    });

    for (image.sections) |*section| {
        const data = image.sectionData(section) catch &.{};
        const value = safedisc.entropy(data);
        try ctx.stdout.print("  {s:<8} {x:0>8}+{x:<7} raw {x:0>6}+{x:<7} entropy {d:.2}{s}\n", .{
            section.name(),
            optional.image_base + section.virtual_address,
            section.virtual_size,
            section.raw_offset,
            section.raw_size,
            value,
            if (value >= safedisc.encrypted_entropy_threshold) "  encrypted" else "",
        });
    }

    switch (safedisc.detect(image)) {
        .encrypted => |detail| try ctx.stdout.print(
            "\nSafeDisc payload: {d} encrypted section(s)\n",
            .{detail.section_count},
        ),
        .plain => try ctx.stdout.writeAll("\nno encrypted sections\n"),
    }

    const states = try safedisc.ImportState.survey(ctx.arena, image);
    if (states.len == 0) return;
    try ctx.stdout.writeAll("\nimports:\n");
    for (states) |state| {
        try ctx.stdout.print("  {s:<16} {d:>3} entries  {t}\n", .{ state.library, state.entry_count, state.kind });
    }
    try ctx.stdout.writeAll(
        \\
        \\An emptied table is SafeDisc's doing: those APIs are resolved at run time through
        \\dplayerx.dll, so a decrypted image is readable but not yet runnable.
        \\
    );
}

test Command {
    const decrypt = try Command.parse(&.{ "decrypt", "LANCER.ICD", "LANCER.EXE", "--key", "0x1234abcd" });
    try std.testing.expectEqualStrings("LANCER.EXE", decrypt.decrypt.out);
    try std.testing.expectEqual(0x1234ABCD, decrypt.decrypt.key.?);
    try std.testing.expectEqual(null, (try Command.parse(&.{ "decrypt", "LANCER.ICD", "LANCER.EXE" })).decrypt.key);
    try std.testing.expectEqual(0x1234ABCD, (try Command.parse(&.{ "imports", "LANCER.ICD", "--key", "1234ABCD" })).imports.key.?);
    try std.testing.expectEqual(0, (try Command.parse(&.{ "imports", "LANCER.ICD", "--key", "0x0" })).imports.key.?);

    try std.testing.expectError(error.Usage, Command.parse(&.{ "imports", "LANCER.ICD", "--key", "0xzz" }));
    try std.testing.expectError(error.Usage, Command.parse(&.{ "imports", "LANCER.ICD", "--kee", "1" }));
    try std.testing.expectError(error.Usage, Command.parse(&.{ "decrypt", "LANCER.ICD" }));
    try std.testing.expectError(error.Usage, Command.parse(&.{ "key", "LANCER.ICD", "extra" }));
}
