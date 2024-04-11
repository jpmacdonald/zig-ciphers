// caesar.zig
const std = @import("std");

/// Encrypts the given plaintext using the Caesar cipher with the provided shift value.
pub fn encrypt(plaintext: []const u8, shift: u8) ![]u8 {
    var ciphertext = try std.ArrayList(u8).initCapacity(std.heap.page_allocator, plaintext.len);
    defer ciphertext.deinit();

    for (plaintext) |char| {
        const shifted = @truncate(u8, char + shift);
        try ciphertext.append(shifted);
    }

    return ciphertext.toOwnedSlice();
}

/// Decrypts the given ciphertext using the Caesar cipher with the provided shift value.
pub fn decrypt(ciphertext: []const u8, shift: u8) ![]u8 {
    var plaintext = try std.ArrayList(u8).initCapacity(std.heap.page_allocator, ciphertext.len);
    defer plaintext.deinit();

    for (ciphertext) |char| {
        const shifted = @truncate(u8, char - shift);
        try plaintext.append(shifted);
    }

    return plaintext.toOwnedSlice();
}