// baconian.zig

const std = @import("std");

const BaconianCodeLength = 5;

const BaconianAlphabet = comptime blk: {
    var alphabet: [26]u5 = undefined;
    var i: u5 = 0;
    for (alphabet) |*code| {
        code.* = i;
        i += 1;
    }
    break :blk alphabet;
};

/// Encrypts the given plaintext using the Baconian cipher.
pub fn encrypt(plaintext: []const u8) ![]u5 {
    // Validate input
    for (plaintext) |char| {
        if (char < 'A' or char > 'Z') return error.InvalidInput;
    }

    var ciphertext = try std.ArrayList(u5).initCapacity(std.heap.page_allocator, plaintext.len * BaconianCodeLength);
    errdefer ciphertext.deinit();

    for (plaintext) |char| {
        const idx = @intCast(usize, char - 'A');
        ciphertext.appendAssumeCapacity(BaconianAlphabet[idx]);
    }

    return ciphertext.toOwnedSlice();
}

/// Decrypts the given ciphertext using the Baconian cipher.
pub fn decrypt(ciphertext: []const u5) ![]u8 {
    // Validate input
    if (ciphertext.len % BaconianCodeLength != 0) return error.InvalidInput;

    var plaintext = try std.ArrayList(u8).initCapacity(std.heap.page_allocator, ciphertext.len / BaconianCodeLength);
    errdefer plaintext.deinit();

    var i: usize = 0;
    while (i < ciphertext.len) {
        const code = ciphertext[i .. i + BaconianCodeLength];
        const idx = std.mem.indexOfScalar(u5, &BaconianAlphabet, code) orelse return error.InvalidInput;
        plaintext.appendAssumeCapacity(@intCast(u8, idx + 'A'));
        i += BaconianCodeLength;
    }

    return plaintext.toOwnedSlice();
}