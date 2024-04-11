// cbc.zig - Cipher Block Chaining (CBC) mode of operation for block ciphers

const std = @import("std");
const crypto = std.crypto;

pub fn encrypt(plaintext: []const u8, key: []const u8, iv: [16]u8) ![]u8 {
    var cipher = crypto.core.Aes128.initEnc(key);
    var ciphertext = try std.ArrayList(u8).initCapacity(std.heap.page_allocator, plaintext.len);
    errdefer ciphertext.deinit();

    var prevBlock: [16]u8 = iv;
    var i: usize = 0;
    while (i < plaintext.len) {
        var block: [16]u8 = undefined;
        std.mem.copy(u8, &block, plaintext[i..][0..16]);
        crypto.utils.xorBlocks(block[0..], &prevBlock, block[0..]);
        prevBlock = cipher.encrypt(block);
        ciphertext.appendSliceAssumeCapacity(&prevBlock);
        i += 16;
    }

    return ciphertext.toOwnedSlice();
}

pub fn decrypt(ciphertext: []const u8, key: []const u8, iv: [16]u8) ![]u8 {
    var cipher = crypto.core.Aes128.initDec(key);
    var plaintext = try std.ArrayList(u8).initCapacity(std.heap.page_allocator, ciphertext.len);
    errdefer plaintext.deinit();

    var prevBlock: [16]u8 = iv;
    var i: usize = 0;
    while (i < ciphertext.len) {
        const block = cipher.decrypt(ciphertext[i..][0..16]);
        crypto.utils.xorBlocks(block[0..], &prevBlock, block[0..]);
        plaintext.appendSliceAssumeCapacity(block[0..]);
        prevBlock = ciphertext[i..][0..16];
        i += 16;
    }

    return plaintext.toOwnedSlice();
}