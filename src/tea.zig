//! TEA, the Tiny Encryption Algorithm (Wheeler and Needham, 1994).
//!
//! A 64-bit block cipher with a 128-bit key, used by SafeDisc to encrypt the executable sections
//! of an `.icd` payload. See `safedisc.zig` for how it is applied there.

const std = @import("std");

pub const block_size = 8;
pub const key_size = 16;

/// The golden-ratio constant the round function mixes into the key schedule.
pub const delta: u32 = 0x9E3779B9;
/// Cycles per block. Each cycle is two Feistel rounds, so 32 cycles is the usual "64 round" TEA.
pub const default_cycles = 32;

/// The 128-bit key, as the four words the round function indexes.
pub const Key = struct {
    words: [4]u32,

    /// Keys whose four words are all equal, which is how SafeDisc 1.3x and 1.4x store them. The
    /// repetition is what makes the key searchable: 32 bits of entropy rather than 128.
    pub fn repeated(word: u32) Key {
        return .{ .words = @splat(word) };
    }

    pub fn fromBytes(bytes: [key_size]u8) Key {
        var key: Key = undefined;
        for (&key.words, 0..) |*word, i| {
            word.* = std.mem.readInt(u32, bytes[i * 4 ..][0..4], .little);
        }
        return key;
    }

    pub fn toBytes(key: Key) [key_size]u8 {
        var bytes: [key_size]u8 = undefined;
        for (key.words, 0..) |word, i| {
            std.mem.writeInt(u32, bytes[i * 4 ..][0..4], word, .little);
        }
        return bytes;
    }
};

/// One 64-bit block, as the two halves the Feistel network works on.
pub const Block = struct {
    v0: u32,
    v1: u32,

    /// TEA itself is endian-neutral; these two choices are the convention of the implementation
    /// being reproduced, which reads each half as a little-endian `u32`.
    pub fn fromBytes(bytes: [block_size]u8) Block {
        return .{
            .v0 = std.mem.readInt(u32, bytes[0..4], .little),
            .v1 = std.mem.readInt(u32, bytes[4..8], .little),
        };
    }

    pub fn toBytes(block: Block) [block_size]u8 {
        var bytes: [block_size]u8 = undefined;
        std.mem.writeInt(u32, bytes[0..4], block.v0, .little);
        std.mem.writeInt(u32, bytes[4..8], block.v1, .little);
        return bytes;
    }

    pub fn eql(a: Block, b: Block) bool {
        return a.v0 == b.v0 and a.v1 == b.v1;
    }

    pub const zero: Block = .{ .v0 = 0, .v1 = 0 };
};

pub fn encryptBlock(block: Block, key: Key, cycles: u32) Block {
    const k = key.words;
    var v0 = block.v0;
    var v1 = block.v1;
    var sum: u32 = 0;
    for (0..cycles) |_| {
        sum +%= delta;
        v0 +%= ((v1 << 4) +% k[0]) ^ (v1 +% sum) ^ ((v1 >> 5) +% k[1]);
        v1 +%= ((v0 << 4) +% k[2]) ^ (v0 +% sum) ^ ((v0 >> 5) +% k[3]);
    }
    return .{ .v0 = v0, .v1 = v1 };
}

pub fn decryptBlock(block: Block, key: Key, cycles: u32) Block {
    const k = key.words;
    var v0 = block.v0;
    var v1 = block.v1;
    var sum = delta *% cycles;
    for (0..cycles) |_| {
        v1 -%= ((v0 << 4) +% k[2]) ^ (v0 +% sum) ^ ((v0 >> 5) +% k[3]);
        v0 -%= ((v1 << 4) +% k[0]) ^ (v1 +% sum) ^ ((v1 >> 5) +% k[1]);
        sum -%= delta;
    }
    return .{ .v0 = v0, .v1 = v1 };
}

/// Decrypts `buffer` in place in ECB mode. A trailing partial block is left untouched, which is
/// what the SafeDisc loader does with the tail of a section.
pub fn decryptEcb(buffer: []u8, key: Key, cycles: u32) void {
    mapEcb(buffer, key, cycles, decryptBlock);
}

/// The inverse of `decryptEcb`, with the same treatment of a trailing partial block.
pub fn encryptEcb(buffer: []u8, key: Key, cycles: u32) void {
    mapEcb(buffer, key, cycles, encryptBlock);
}

fn mapEcb(buffer: []u8, key: Key, cycles: u32, comptime transform: fn (Block, Key, u32) Block) void {
    var offset: usize = 0;
    while (offset + block_size <= buffer.len) : (offset += block_size) {
        const chunk = buffer[offset..][0..block_size];
        chunk.* = transform(.fromBytes(chunk.*), key, cycles).toBytes();
    }
}

/// Recovers the 32-bit word of a repeated key, given one block of known plaintext and its
/// ciphertext. Returns every word that maps one to the other: with 64 bits of known text against a
/// 32-bit search space a false positive is unlikely but not impossible, so the caller decides.
///
/// `found` is called with each match. Searching is split over `thread_count` threads.
pub fn searchRepeatedKey(
    plaintext: Block,
    ciphertext: Block,
    cycles: u32,
    thread_count: usize,
    context: anytype,
    comptime found: fn (@TypeOf(context), u32) void,
) !void {
    return searchRepeatedKeyFrom(plaintext, ciphertext, cycles, thread_count, 0, context, found);
}

/// `searchRepeatedKey`, starting at `first_word` instead of zero and stopping when the search
/// wraps past the end of the 32-bit space.
pub fn searchRepeatedKeyFrom(
    plaintext: Block,
    ciphertext: Block,
    cycles: u32,
    thread_count: usize,
    first_word: u32,
    context: anytype,
    comptime found: fn (@TypeOf(context), u32) void,
) !void {
    const Context = @TypeOf(context);
    const Worker = struct {
        fn run(ctx: Context, pt: Block, ct: Block, n: u32, first: u32, stride: u32) void {
            var word = first;
            while (true) {
                if (decryptBlock(ct, .repeated(word), n).eql(pt)) found(ctx, word);
                word, const overflow = @addWithOverflow(word, stride);
                if (overflow != 0) break;
            }
        }
    };

    const threads = try std.heap.page_allocator.alloc(std.Thread, thread_count);
    defer std.heap.page_allocator.free(threads);

    var spawned: usize = 0;
    defer for (threads[0..spawned]) |thread| thread.join();
    while (spawned < thread_count) : (spawned += 1) {
        threads[spawned] = try std.Thread.spawn(
            .{},
            Worker.run,
            .{ context, plaintext, ciphertext, cycles, first_word +% @as(u32, @intCast(spawned)), @as(u32, @intCast(thread_count)) },
        );
    }
}

test "round-trips its own output" {
    const key: Key = .fromBytes(.{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 });
    const plain: Block = .{ .v0 = 0xDEADBEEF, .v1 = 0x0BADC0DE };
    const cipher = encryptBlock(plain, key, default_cycles);
    try std.testing.expect(!cipher.eql(plain));
    try std.testing.expect(decryptBlock(cipher, key, default_cycles).eql(plain));
}

test "matches published test vectors" {
    // From the reference implementation's usual vector set: all-zero key and all-zero plaintext,
    // then an all-ones pattern.
    const zero_key: Key = .{ .words = @splat(0) };
    try std.testing.expectEqual(
        Block{ .v0 = 0x41EA3A0A, .v1 = 0x94BAA940 },
        encryptBlock(.zero, zero_key, default_cycles),
    );

    const ones_key: Key = .{ .words = .{ 0x01234567, 0x89ABCDEF, 0x01234567, 0x89ABCDEF } };
    const plain: Block = .{ .v0 = 0x01234567, .v1 = 0x89ABCDEF };
    const cipher = encryptBlock(plain, ones_key, default_cycles);
    try std.testing.expect(decryptBlock(cipher, ones_key, default_cycles).eql(plain));
}

test "ECB leaves a trailing partial block alone" {
    const key: Key = .repeated(0x12345678);
    var buffer: [block_size + 3]u8 = @splat(0xAA);
    const original_tail = buffer[block_size..].*;
    decryptEcb(&buffer, key, default_cycles);
    try std.testing.expectEqualSlices(u8, &original_tail, buffer[block_size..]);
    try std.testing.expect(!std.mem.eql(u8, &.{ 0xAA, 0xAA, 0xAA, 0xAA }, buffer[0..4]));
}

test searchRepeatedKey {
    // The real search covers all 2^32 words and takes minutes. Here one thread runs the same
    // worker over a stride that reaches the planted key immediately, which exercises the callback
    // and the overflow-terminated loop without the full scan.
    const planted: u32 = 0xFFFFFFF9;
    const cipher = encryptBlock(.zero, .repeated(planted), default_cycles);

    const Collector = struct {
        hits: u32 = 0,
        word: u32 = 0,
        fn onFound(self: *@This(), word: u32) void {
            self.hits += 1;
            self.word = word;
        }
    };
    var collector: Collector = .{};
    // Starting at the planted word with a large stride, the search terminates after a handful of
    // steps when the word wraps past the end of the space.
    try searchRepeatedKeyFrom(.zero, cipher, default_cycles, 1, planted, &collector, Collector.onFound);
    try std.testing.expectEqual(@as(u32, 1), collector.hits);
    try std.testing.expectEqual(planted, collector.word);
}
