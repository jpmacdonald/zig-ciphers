// ecb.zig - Electronic Codebook mode (ECB) for block ciphers

const std = @import("std");
const crypto = std.crypto;

pub fn encrypt(plaintext: []const u8, key: []const u8) ![]u8 {
    var cipher = crypto.core.Aes128.initEnc(key);
    var ciphertext = try std.ArrayList(u8).initCapacity(std.heap.page_allocator, plaintext.len);
    errdefer ciphertext.deinit();

    var i: usize = 0;
    while (i < plaintext.len) {
        const block = cipher.encrypt(plaintext[i..][0..16]);
        ciphertext.appendSliceAssumeCapacity(block);
        i += 16;
    }

    return ciphertext.toOwnedSlice();
}

pub fn decrypt(ciphertext: []const u8, key: []const u8) ![]u8 {
    var cipher = crypto.core.Aes128.initDec(key);
    var plaintext = try std.ArrayList(u8).initCapacity(std.heap.page_allocator, ciphertext.len);
    errdefer plaintext.deinit();

    var i: usize = 0;
    while (i < ciphertext.len) {
        const block = cipher.decrypt(ciphertext[i..][0..16]);
        plaintext.appendSliceAssumeCapacity(block);
        i += 16;
    }

    return plaintext.toOwnedSlice();
}