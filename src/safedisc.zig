//! Macrovision SafeDisc version 1: recovering the payload executable from an `.icd` file.
//!
//! A SafeDisc 1 title ships as a pair. The `.exe` is a loader that performs the disc and debugger
//! checks, and the real program lives beside it in an `.icd`, a complete PE image whose code and
//! data sections are encrypted. The loader decrypts those sections into a child process.
//!
//! The cipher is TEA in ECB mode, 32 cycles, with a 128-bit key whose four words are all equal
//! (see `tea.Key.repeated`). That repetition leaves 32 bits of key material, small enough to
//! recover from the file alone: see `recoverKey`.
//!
//! Decrypting yields readable code and data, which is what static analysis needs. It does not
//! yield a runnable image: see `ImportState` for what the loader still does at run time.

const std = @import("std");
const Allocator = std.mem.Allocator;

const pe = @import("pe.zig");
const tea = @import("tea.zig");

/// SafeDisc 1 encrypts with this configuration. The loader's own decrypt routine reads the cycle
/// count and delta from its `.rdata`, where they hold these values.
pub const cycles = tea.default_cycles;

/// Shannon entropy over a byte buffer, in bits per byte.
pub fn entropy(bytes: []const u8) f64 {
    if (bytes.len == 0) return 0;
    var counts: [256]usize = @splat(0);
    for (bytes) |b| counts[b] += 1;

    var total: f64 = 0;
    const len: f64 = @floatFromInt(bytes.len);
    for (counts) |count| {
        if (count == 0) continue;
        const p = @as(f64, @floatFromInt(count)) / len;
        total -= p * @log2(p);
    }
    return total;
}

/// Sections above this entropy are treated as candidates for decryption. Encrypted data sits just
/// under 8.0; compiled code and initialized data sit well below.
pub const encrypted_entropy_threshold = 7.5;

/// Whether an image looks like a SafeDisc payload, and why.
pub const Detection = union(enum) {
    /// At least one section has ciphertext-level entropy.
    encrypted: struct { section_count: usize },
    /// A PE with nothing left to decrypt.
    plain,

    pub fn isEncrypted(detection: Detection) bool {
        return detection == .encrypted;
    }
};

pub fn detect(image: pe.Image) Detection {
    var count: usize = 0;
    for (image.sections) |*section| {
        const data = image.sectionData(section) catch continue;
        if (entropy(data) >= encrypted_entropy_threshold) count += 1;
    }
    return if (count == 0) .plain else .{ .encrypted = .{ .section_count = count } };
}

/// Plaintext blocks a key search tests its candidate against. An encrypted section's most repeated
/// ciphertext block is the encryption of whichever 8-byte value the section repeats most, which is
/// alignment padding: zero in data, `int3` in code between MSVC functions.
pub const known_plaintexts = [_]tea.Block{
    .zero,
    .fromBytes(@splat(0xCC)),
    .fromBytes(@splat(0x90)),
};

pub const KeyRecovery = struct {
    key: tea.Key,
    /// The padding value whose ciphertext the search matched.
    plaintext: tea.Block,
    /// The section the ciphertext came from.
    section_name: []const u8,

    /// TEA has equivalent keys: flipping the top bit of both words of either half leaves the
    /// cipher unchanged, so a search over repeated keys reports the word and its twin. Reporting
    /// the smaller of the two keeps the result stable.
    pub fn canonicalWord(word: u32) u32 {
        return @min(word, word ^ 0x8000_0000);
    }
};

pub const RecoverError = error{
    /// No section looked encrypted.
    NotEncrypted,
    /// A section is encrypted, but no repeated key maps its commonest block to known padding.
    KeyNotFound,
} || Allocator.Error || std.Thread.SpawnError;

/// Finds the section key by brute force over the 32-bit space of repeated keys.
///
/// The search needs a known plaintext. Rather than assume one, it takes the most frequent
/// ciphertext block of the most encrypted-looking section, which is padding, and accepts any key
/// that maps it to one of `known_plaintexts`. Progress is split over `thread_count` threads.
pub fn recoverKey(gpa: Allocator, image: pe.Image, thread_count: usize) RecoverError!KeyRecovery {
    var best: ?struct { section: *align(1) pe.SectionHeader, block: tea.Block } = null;
    var best_repeats: usize = 0;

    for (image.sections) |*section| {
        const data = image.sectionData(section) catch continue;
        if (entropy(data) < encrypted_entropy_threshold) continue;
        const common = try mostCommonBlock(gpa, data);
        if (common.repeats > best_repeats) {
            best_repeats = common.repeats;
            best = .{ .section = section, .block = common.block };
        }
    }
    const candidate = best orelse return error.NotEncrypted;

    const Search = struct {
        found: std.atomic.Value(u64) = .init(no_match),
        ciphertext: tea.Block,

        /// Packs "matched" plus the two results into one atomically stored value.
        const no_match = std.math.maxInt(u64);

        fn onFound(search: *@This(), word: u32, plaintext_index: usize) void {
            const packed_value = (@as(u64, plaintext_index) << 32) | word;
            _ = search.found.cmpxchgStrong(no_match, packed_value, .monotonic, .monotonic);
        }
    };
    var search: Search = .{ .ciphertext = candidate.block };

    const Trial = struct {
        fn run(s: *Search, first: u32, stride: u32) void {
            var word = first;
            while (s.found.load(.monotonic) == Search.no_match) {
                const decrypted = tea.decryptBlock(s.ciphertext, .repeated(word), cycles);
                for (known_plaintexts, 0..) |plaintext, i| {
                    if (decrypted.eql(plaintext)) s.onFound(word, i);
                }
                word, const overflow = @addWithOverflow(word, stride);
                if (overflow != 0) break;
            }
        }
    };

    const threads = try gpa.alloc(std.Thread, @max(thread_count, 1));
    defer gpa.free(threads);
    var spawned: usize = 0;
    while (spawned < threads.len) : (spawned += 1) {
        threads[spawned] = try std.Thread.spawn(
            .{},
            Trial.run,
            .{ &search, @as(u32, @intCast(spawned)), @as(u32, @intCast(threads.len)) },
        );
    }
    for (threads[0..spawned]) |thread| thread.join();

    const result = search.found.load(.monotonic);
    if (result == Search.no_match) return error.KeyNotFound;
    return .{
        .key = .repeated(KeyRecovery.canonicalWord(@truncate(result))),
        .plaintext = known_plaintexts[@intCast(result >> 32)],
        .section_name = candidate.section.name(),
    };
}

fn mostCommonBlock(gpa: Allocator, data: []const u8) Allocator.Error!struct { block: tea.Block, repeats: usize } {
    var counts: std.AutoHashMapUnmanaged(u64, usize) = .empty;
    defer counts.deinit(gpa);

    var offset: usize = 0;
    while (offset + tea.block_size <= data.len) : (offset += tea.block_size) {
        const value = std.mem.readInt(u64, data[offset..][0..tea.block_size], .little);
        const entry = try counts.getOrPutValue(gpa, value, 0);
        entry.value_ptr.* += 1;
    }

    var best_value: u64 = 0;
    var best_count: usize = 0;
    var it = counts.iterator();
    while (it.next()) |entry| {
        if (entry.value_ptr.* > best_count) {
            best_count = entry.value_ptr.*;
            best_value = entry.key_ptr.*;
        }
    }

    var bytes: [tea.block_size]u8 = undefined;
    std.mem.writeInt(u64, &bytes, best_value, .little);
    return .{ .block = .fromBytes(bytes), .repeats = best_count };
}

pub const DecryptedSection = struct {
    name: []const u8,
    entropy_before: f64,
    entropy_after: f64,
};

/// Decrypts every encrypted section of `image` in place, and reports what was touched.
///
/// Which sections are encrypted is decided by measurement rather than by name: a section is
/// decrypted only if doing so lowers its entropy. Decrypting an already-plain section would raise
/// it, so a wrong guess is caught and rolled back instead of corrupting the output.
pub fn decrypt(gpa: Allocator, image: pe.Image, key: tea.Key) Allocator.Error![]DecryptedSection {
    var decrypted: std.ArrayList(DecryptedSection) = .empty;
    errdefer decrypted.deinit(gpa);

    for (image.sections) |*section| {
        const data = image.sectionData(section) catch continue;
        const before = entropy(data);
        if (before < encrypted_entropy_threshold) continue;

        tea.decryptEcb(data, key, cycles);
        const after = entropy(data);
        if (after >= before) {
            // Not actually ciphertext, or not this key: undo it.
            tea.encryptEcb(data, key, cycles);
            continue;
        }
        try decrypted.append(gpa, .{
            .name = section.name(),
            .entropy_before = before,
            .entropy_after = after,
        });
    }
    return decrypted.toOwnedSlice(gpa);
}

/// What remains between a decrypted image and a runnable one.
///
/// SafeDisc empties the `kernel32.dll` and `user32.dll` import tables and resolves those APIs at
/// run time through `dplayerx.dll`, so in a decrypted image every slot of those two tables holds a
/// placeholder rather than a thunk. Calls to them reach a stub that pushes an API index and a
/// library index (0 for `kernel32`, 1 for `user32`) before calling into `dplayerx`.
///
/// Static analysis is unaffected for everything else: all other imports are intact, and all code
/// and data are readable. Rebuilding these two tables is what a runnable image additionally needs.
pub const ImportState = struct {
    library: []const u8,
    /// Number of entries before the table's first null terminator.
    entry_count: usize,
    kind: Kind,

    pub const Kind = enum {
        /// Entries are plausible hint/name or ordinal references.
        intact,
        /// The table terminates immediately, so the image asks the loader for nothing by name.
        emptied,
        /// Entries are present but do not look like references into this image.
        placeholders,
    };

    /// Import RVAs below this are plausible; the placeholders SafeDisc leaves are far larger.
    const max_plausible_rva = 0x1000_0000;

    pub fn survey(gpa: Allocator, image: pe.Image) Allocator.Error![]ImportState {
        var states: std.ArrayList(ImportState) = .empty;
        errdefer states.deinit(gpa);

        var it = image.imports() orelse return states.toOwnedSlice(gpa);
        while (it.next()) |entry| {
            const table_rva = if (entry.descriptor.lookup_table_rva != 0)
                entry.descriptor.lookup_table_rva
            else
                entry.descriptor.address_table_rva;
            const offset = image.fileOffset(table_rva) orelse continue;

            var count: usize = 0;
            var plausible = true;
            while (offset + (count + 1) * 4 <= image.bytes.len) : (count += 1) {
                const thunk = std.mem.readInt(u32, image.bytes[offset + count * 4 ..][0..4], .little);
                if (thunk == 0) break;
                // The high bit marks an ordinal import, which carries no RVA to check.
                if (thunk & 0x8000_0000 == 0 and thunk > max_plausible_rva) plausible = false;
            }

            try states.append(gpa, .{
                .library = entry.name,
                .entry_count = count,
                .kind = if (count == 0) .emptied else if (plausible) .intact else .placeholders,
            });
        }
        return states.toOwnedSlice(gpa);
    }
};

/// Recovering the emptied `kernel32` and `user32` import tables.
///
/// SafeDisc does not discard those tables, it obscures them. Three things are done to them, all of
/// which are reversible from the file:
///
/// 1. Every thunk, in both the lookup table and the address table, is XORed with the low word of
///    the TEA key, leaving a value far too large to be an RVA.
/// 2. The first thunk of each table is zeroed instead, which terminates the table where it starts.
///    That is what makes a tool reading the image see no imports at all. The hint/name entry it
///    pointed at survives in `.rdata`, unreferenced.
/// 3. The API name strings are encrypted with a rolling XOR: each byte is combined with the
///    previous *ciphertext* byte, the first with a seed. A string's terminator therefore appears as
///    a repeat of the byte before it.
pub const imports = struct {
    /// Bytes a recovered API name may contain. Decoding with a wrong seed leaves this set almost
    /// immediately, which is what makes the seed searchable.
    fn isNameByte(c: u8) bool {
        return std.ascii.isAlphanumeric(c) or c == '_' or c == '@' or c == '?' or c == '$';
    }

    fn isNameStart(c: u8) bool {
        return std.ascii.isAlphabetic(c) or c == '_' or c == '?';
    }

    /// A hint/name entry: a 2-byte hint followed by the encrypted, NUL-terminated name.
    pub const Name = struct {
        rva: u32,
        text: []const u8,
        /// Bytes the entry occupies, from `rva`, including hint and terminator.
        encoded_len: usize,
    };

    /// Decodes the hint/name entry at `rva`. Returns null if the bytes there are not a name, which
    /// is how both the seed search and the scan for unreferenced entries reject candidates.
    pub fn decodeName(gpa: Allocator, image: pe.Image, rva: u32, seed: u8) Allocator.Error!?Name {
        const start = image.fileOffset(rva + 2) orelse return null;
        var text: std.ArrayList(u8) = .empty;
        errdefer text.deinit(gpa);

        var previous = seed;
        var offset = start;
        while (offset < image.bytes.len) : (offset += 1) {
            const cipher = image.bytes[offset];
            const plain = cipher ^ previous;
            previous = cipher;
            if (plain == 0) {
                if (text.items.len < 3) break;
                return .{
                    .rva = rva,
                    .text = try text.toOwnedSlice(gpa),
                    .encoded_len = 2 + (offset + 1 - start),
                };
            }
            const ok = if (text.items.len == 0) isNameStart(plain) else isNameByte(plain);
            if (!ok) break;
            try text.append(gpa, plain);
            if (text.items.len > 128) break;
        }
        text.deinit(gpa);
        return null;
    }

    /// Finds the seed the name encryption starts from, by trying all 256 and keeping the one that
    /// decodes every entry in `rvas`. The seed of this release is the XOR of the four key bytes,
    /// but that derivation is **unverified** against other titles, so it is measured, not assumed.
    ///
    /// Only the first character of a name depends on the seed, so two seeds always survive: they
    /// differ by `0x20`, the ASCII case bit, and decode identical names save for the case of that
    /// first letter. Win32 API names are overwhelmingly capitalised (`lstrlenA` and `wsprintfA`
    /// being the usual exceptions), so the tie goes to whichever seed capitalises more of them.
    pub fn recoverSeed(gpa: Allocator, image: pe.Image, rvas: []const u32) Allocator.Error!?u8 {
        var best: ?u8 = null;
        var best_score: usize = 0;
        var best_capitals: usize = 0;

        for (0..256) |candidate| {
            const seed: u8 = @intCast(candidate);
            var score: usize = 0;
            var capitals: usize = 0;
            for (rvas) |rva| {
                if (try decodeName(gpa, image, rva, seed)) |name| {
                    defer gpa.free(name.text);
                    score += 1;
                    if (std.ascii.isUpper(name.text[0])) capitals += 1;
                }
            }
            if (score > best_score or (score == best_score and capitals > best_capitals)) {
                best_score = score;
                best_capitals = capitals;
                best = seed;
            }
        }
        return if (best_score == rvas.len and rvas.len > 0) best else null;
    }

    pub const Entry = struct {
        slot: usize,
        name: Name,
        /// True when the slot was zeroed and its name was recovered by elimination.
        restored: bool,
    };

    pub const Library = struct {
        name: []const u8,
        /// Index of the descriptor in the import directory.
        descriptor_index: usize,
        lookup_table_rva: u32,
        address_table_rva: u32,
        entries: []Entry,
    };

    pub const Recovery = struct {
        seed: u8,
        libraries: []Library,
    };

    pub const Error = error{
        /// No library has an emptied table, so there is nothing to recover.
        NoEmptiedTables,
        /// The name encryption seed could not be determined.
        SeedNotFound,
        /// A zeroed slot has no unreferenced name entry to take.
        SlotUnrecoverable,
    } || Allocator.Error;

    /// Works out what each emptied table originally held, without modifying the image.
    pub fn recover(gpa: Allocator, image: pe.Image, key: tea.Key) Error!Recovery {
        const key_word = key.words[0];

        var libraries: std.ArrayList(Library) = .empty;
        var referenced: std.AutoHashMapUnmanaged(u32, void) = .empty;
        defer referenced.deinit(gpa);

        var index: usize = 0;
        var it = image.imports() orelse return error.NoEmptiedTables;
        while (it.next()) |descriptor| : (index += 1) {
            const lookup_rva = descriptor.descriptor.lookup_table_rva;
            const address_rva = descriptor.descriptor.address_table_rva;
            const offset = image.fileOffset(lookup_rva) orelse continue;
            // An emptied table is one whose first slot terminates it.
            if (std.mem.readInt(u32, image.bytes[offset..][0..4], .little) != 0) continue;

            var entries: std.ArrayList(Entry) = .empty;
            var slot: usize = 1;
            while (offset + (slot + 1) * 4 <= image.bytes.len) : (slot += 1) {
                const thunk = std.mem.readInt(u32, image.bytes[offset + slot * 4 ..][0..4], .little);
                if (thunk == 0) break;
                const rva = thunk ^ key_word;
                try referenced.put(gpa, rva, {});
                try entries.append(gpa, .{
                    .slot = slot,
                    .name = .{ .rva = rva, .text = "", .encoded_len = 0 },
                    .restored = false,
                });
            }
            if (entries.items.len == 0) {
                entries.deinit(gpa);
                continue;
            }
            try libraries.append(gpa, .{
                .name = descriptor.name,
                .descriptor_index = index,
                .lookup_table_rva = lookup_rva,
                .address_table_rva = address_rva,
                .entries = try entries.toOwnedSlice(gpa),
            });
        }
        if (libraries.items.len == 0) return error.NoEmptiedTables;

        var rvas: std.ArrayList(u32) = .empty;
        defer rvas.deinit(gpa);
        var referenced_it = referenced.keyIterator();
        while (referenced_it.next()) |rva| try rvas.append(gpa, rva.*);

        const seed = try recoverSeed(gpa, image, rvas.items) orelse return error.SeedNotFound;

        // Decode the names the surviving thunks point at.
        for (libraries.items) |library| {
            for (library.entries) |*entry| {
                entry.name = try decodeName(gpa, image, entry.name.rva, seed) orelse
                    return error.SeedNotFound;
            }
        }

        // The zeroed first slot of each table pointed at a hint/name entry that is still there,
        // just no longer referenced. Find the unreferenced entries and give each to the library
        // whose surviving names lie closest: the two libraries' names occupy separate runs, so
        // nearest-neighbour separates them even though their address ranges overlap.
        var lo: u32 = std.math.maxInt(u32);
        var hi: u32 = 0;
        for (rvas.items) |rva| {
            lo = @min(lo, rva);
            hi = @max(hi, rva);
        }

        var scan = lo;
        var orphans: std.ArrayList(Name) = .empty;
        defer orphans.deinit(gpa);
        while (scan <= hi) {
            const name = try decodeName(gpa, image, scan, seed) orelse {
                scan += 2;
                continue;
            };
            if (referenced.contains(scan)) {
                gpa.free(name.text);
            } else {
                try orphans.append(gpa, name);
            }
            scan += @intCast(std.mem.alignForward(usize, name.encoded_len, 2));
        }

        for (libraries.items) |*library| {
            var best: ?usize = null;
            var best_distance: u32 = std.math.maxInt(u32);
            for (orphans.items, 0..) |orphan, i| {
                if (orphan.text.len == 0) continue;
                var distance: u32 = std.math.maxInt(u32);
                for (library.entries) |entry| {
                    const delta = if (entry.name.rva > orphan.rva)
                        entry.name.rva - orphan.rva
                    else
                        orphan.rva - entry.name.rva;
                    distance = @min(distance, delta);
                }
                if (distance < best_distance) {
                    best_distance = distance;
                    best = i;
                }
            }
            const chosen = best orelse return error.SlotUnrecoverable;

            var restored: std.ArrayList(Entry) = .empty;
            try restored.append(gpa, .{ .slot = 0, .name = orphans.items[chosen], .restored = true });
            try restored.appendSlice(gpa, library.entries);
            gpa.free(library.entries);
            library.entries = try restored.toOwnedSlice(gpa);
            // Claim it, so a second library cannot take the same entry.
            orphans.items[chosen].text = "";
        }

        return .{ .seed = seed, .libraries = try libraries.toOwnedSlice(gpa) };
    }

    /// Writes the recovered tables back into `image`: real RVAs in both thunk tables, and the API
    /// names in the clear. Afterwards the image's import directory parses like any other PE's.
    pub fn rebuild(gpa: Allocator, image: pe.Image, key: tea.Key) Error!Recovery {
        const recovery = try recover(gpa, image, key);
        for (recovery.libraries) |library| {
            const lookup = image.fileOffset(library.lookup_table_rva).?;
            const address = image.fileOffset(library.address_table_rva).?;
            for (library.entries) |entry| {
                for ([_]u32{ lookup, address }) |table| {
                    const slot = table + entry.slot * 4;
                    std.mem.writeInt(u32, image.bytes[slot..][0..4], entry.name.rva, .little);
                }
                // Replace the encrypted name with the decoded one, terminator included.
                const text = image.fileOffset(entry.name.rva + 2).?;
                @memcpy(image.bytes[text..][0..entry.name.text.len], entry.name.text);
                image.bytes[text + entry.name.text.len] = 0;
            }
        }
        return recovery;
    }
};

test entropy {
    const uniform: [256]u8 = blk: {
        var bytes: [256]u8 = undefined;
        for (&bytes, 0..) |*b, i| b.* = @intCast(i);
        break :blk bytes;
    };
    try std.testing.expectApproxEqAbs(@as(f64, 8.0), entropy(&uniform), 0.001);
    try std.testing.expectApproxEqAbs(@as(f64, 0.0), entropy(&[_]u8{0} ** 64), 0.001);
    try std.testing.expectEqual(@as(f64, 0), entropy(""));
}

test "recovers a planted key and decrypts" {
    const gpa = std.testing.allocator;
    const body_size = 0x4000;
    var image_bytes = try gpa.alloc(u8, 0x400 + body_size);
    defer gpa.free(image_bytes);
    @memset(image_bytes, 0);

    // A minimal PE with one section full of padding plus noise, so that entropy is high once
    // encrypted and the commonest block is the padding.
    const dos: *align(1) pe.DosHeader = @ptrCast(image_bytes[0..@sizeOf(pe.DosHeader)]);
    dos.magic = pe.dos_magic.*;
    dos.nt_offset = 0x80;
    image_bytes[0x80..][0..4].* = pe.nt_signature.*;
    const file_header: *align(1) pe.FileHeader = @ptrCast(image_bytes[0x84..][0..@sizeOf(pe.FileHeader)]);
    file_header.* = std.mem.zeroes(pe.FileHeader);
    file_header.machine = .i386;
    file_header.section_count = 1;
    file_header.optional_header_size = @sizeOf(pe.OptionalHeader32) + 16 * @sizeOf(pe.DataDirectory);
    const optional: *align(1) pe.OptionalHeader32 = @ptrCast(image_bytes[0x98..][0..@sizeOf(pe.OptionalHeader32)]);
    optional.* = std.mem.zeroes(pe.OptionalHeader32);
    optional.magic = .pe32;
    optional.directory_count = 16;

    const sections_offset = 0x98 + @sizeOf(pe.OptionalHeader32) + 16 * @sizeOf(pe.DataDirectory);
    const section: *align(1) pe.SectionHeader = @ptrCast(image_bytes[sections_offset..][0..@sizeOf(pe.SectionHeader)]);
    section.* = std.mem.zeroes(pe.SectionHeader);
    section.name_bytes = ".text\x00\x00\x00".*;
    section.virtual_address = 0x1000;
    section.virtual_size = body_size;
    section.raw_offset = 0x400;
    section.raw_size = body_size;

    // Stand in for a compiled code section: bytes from a small alphabet, so entropy is well under
    // the threshold once decrypted, with `int3` padding as the one repeated block.
    const body = image_bytes[0x400..][0..body_size];
    var prng: std.Random.DefaultPrng = .init(0x5A1A);
    const random = prng.random();
    for (body) |*b| b.* = random.intRangeLessThan(u8, 0x40, 0x60);
    var block: usize = 0;
    while (block < body.len / tea.block_size) : (block += 37) {
        @memset(body[block * tea.block_size ..][0..tea.block_size], 0xCC);
    }

    const planted: u32 = 0x434B4DAD;
    const key: tea.Key = .repeated(planted);
    tea.encryptEcb(body, key, cycles);

    const image: pe.Image = try .parse(image_bytes);
    try std.testing.expect(detect(image).isEncrypted());

    const recovery = try recoverKey(gpa, image, try std.Thread.getCpuCount());
    try std.testing.expectEqual(KeyRecovery.canonicalWord(planted), recovery.key.words[0]);
    try std.testing.expectEqualStrings(".text", recovery.section_name);

    const report = try decrypt(gpa, image, recovery.key);
    defer gpa.free(report);
    try std.testing.expectEqual(@as(usize, 1), report.len);
    try std.testing.expect(report[0].entropy_after < report[0].entropy_before);
    try std.testing.expectEqual(@as(u8, 0xCC), body[0]);
    try std.testing.expectEqual(Detection.plain, detect(image));
}
