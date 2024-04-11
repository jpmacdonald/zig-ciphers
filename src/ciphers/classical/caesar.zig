// caesar.zig

const std = @import("std");

/// Encrypts the given plaintext using the Caesar cipher with the provided shift value.
pub fn encrypt(plaintext: []const u8, shift: u8) ![]u8 {
    // Validate input
    if (plaintext.len == 0) return error.InvalidInput;

    // Precompute shifted characters
    const ShiftedChars = comptime blk: {
        var shifted: [256]u8 = undefined;
        for (shifted) |*s, i| {
            s.* = @intCast(u8, i + shift);
        }
        break :blk shifted;
    };

    // Initialize ciphertext ArrayList
    var ciphertext = try std.ArrayList(u8).initCapacity(std.heap.page_allocator, plaintext.len);
    errdefer ciphertext.deinit();

    // Encrypt plaintext
    for (plaintext) |char| {
        ciphertext.appendAssumeCapacity(ShiftedChars[char]);
    }

    return ciphertext.toOwnedSlice();
}

/// Decrypts the given ciphertext using the Caesar cipher with the provided shift value.
pub fn decrypt(ciphertext: []const u8, shift: u8) ![]u8 {
    // Validate input
    if (ciphertext.len == 0) return error.InvalidInput;

    // Precompute shifted characters
    const ShiftedChars = comptime blk: {
        var shifted: [256]u8 = undefined;
        for (shifted) |*s, i| {
            s.* = @intCast(u8, i - shift);
        }
        break :blk shifted;
    };

    // Initialize plaintext ArrayList
    var plaintext = try std.ArrayList(u8).initCapacity(std.heap.page_allocator, ciphertext.len);
    errdefer plaintext.deinit();

    // Decrypt ciphertext
    for (ciphertext) |char| {
        plaintext.appendAssumeCapacity(ShiftedChars[char]);
    }

    return plaintext.toOwnedSlice();
}