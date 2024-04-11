// transposition.zig

const std = @import("std");

/// Encrypts the given plaintext using a transposition cipher with the provided key.
pub fn encrypt(plaintext: []const u8, key: []const u8) ![]u8 {
    // Input validation
    if (plaintext.len == 0 or key.len == 0) return error.InvalidInput;

    const len = plaintext.len;
    const cols = key.len;
    const rows = (len + cols - 1) / cols; // Ceiling division

    var ciphertext = try std.ArrayList(u8).initCapacity(std.heap.page_allocator, len);
    errdefer ciphertext.deinit();

    var matrix: [cols][rows]u8 = undefined;
    var idx: usize = 0;
    for (plaintext) |char| {
        const col = idx % cols;
        const row = idx / cols;
        matrix[col][row] = char;
        idx += 1;
    }

    for (key) |k, col| {
        for (matrix[k]) |char, row| {
            ciphertext.appendAssumeCapacity(char);
        }
    }

    return ciphertext.toOwnedSlice();
}

/// Decrypts the given ciphertext using a transposition cipher with the provided key.
pub fn decrypt(ciphertext: []const u8, key: []const u8) ![]u8 {
    // Input validation
    if (ciphertext.len == 0 or key.len == 0) return error.InvalidInput;

    const len = ciphertext.len;
    const cols = key.len;
    const rows = (len + cols - 1) / cols; // Ceiling division

    var plaintext = try std.ArrayList(u8).initCapacity(std.heap.page_allocator, len);
    errdefer plaintext.deinit();

    var matrix: [cols][rows]u8 = undefined;
    var idx: usize = 0;
    for (key) |k, col| {
        for (matrix[k]) |*cell, row| {
            cell.* = ciphertext[idx];
            idx += 1;
        }
    }

    for (matrix) |col| {
        for (col) |char| {
            plaintext.appendAssumeCapacity(char);
        }
    }

    return plaintext.toOwnedSlice();
}