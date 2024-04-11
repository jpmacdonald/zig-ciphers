// vignere.zig

const std = @import("std");

/// Encrypts the given plaintext using the Vigenère cipher with the provided key.
pub fn encrypt(plaintext: []const u8, key: []const u8) ![]u8 {
    // Validate inputs
    if (plaintext.len == 0 or key.len == 0) return error.InvalidInput;

    // Precompute key shifts
    const KeyShifts = comptime blk: {
        var shifts: [key.len]u8 = undefined;
        for (key) |k, i| {
            shifts[i] = k;
        }
        break :blk shifts;
    };

    // Initialize ciphertext ArrayList
    var ciphertext = try std.ArrayList(u8).initCapacity(std.heap.page_allocator, plaintext.len);
    errdefer ciphertext.deinit();

    // Encrypt plaintext
    for (plaintext) |char, i| {
        const shift = KeyShifts[i % key.len];
        const shifted = @intCast(u8, char + shift);
        ciphertext.appendAssumeCapacity(shifted);
    }

    return ciphertext.toOwnedSlice();
}

/// Decrypts the given ciphertext using the Vigenère cipher with the provided key.
pub fn decrypt(ciphertext: []const u8, key: []const u8) ![]u8 {
    // Validate inputs
    if (ciphertext.len == 0 or key.len == 0) return error.InvalidInput;

    // Precompute key shifts
    const KeyShifts = comptime blk: {
        var shifts: [key.len]u8 = undefined;
        for (key) |k, i| {
            shifts[i] = k;
        }
        break :blk shifts;
    };

    // Initialize plaintext ArrayList
    var plaintext = try std.ArrayList(u8).initCapacity(std.heap.page_allocator, ciphertext.len);
    errdefer plaintext.deinit();

    // Decrypt ciphertext
    for (ciphertext) |char, i| {
        const shift = KeyShifts[i % key.len];
        const shifted = @intCast(u8, char - shift);
        plaintext.appendAssumeCapacity(shifted);
    }

    return plaintext.toOwnedSlice();
}