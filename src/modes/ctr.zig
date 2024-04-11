// ctr.zig - Counter Mode (CTR) for block ciphers

const std = @import("std");
const crypto = std.crypto;

pub fn encrypt(plaintext: []const u8, key: []const u8, iv: [16]u8) ![]u8 {
    var cipher = crypto.core.Aes128.initEnc(key);
    var ciphertext = try std.ArrayList(u8).initCapacity(std.heap.page_allocator, plaintext.len);
    errdefer ciphertext.deinit();

    var counter: [16]u8 = iv;
    var i: usize = 0;
    while (i < plaintext.len) {
        const keystream = cipher.encrypt(counter);
        crypto.utils.xorBlocks(keystream[0..], plaintext[i..][0..16], keystream[0..]);
        ciphertext.appendSliceAssumeCapacity(keystream[0..]);
        crypto.utils.incrementCounter(&counter);
        i += 16;
    }

    return ciphertext.toOwnedSlice();
}

pub fn decrypt(ciphertext: []const u8, key: []const u8, iv: [16]u8) ![]u8 {
    var cipher = crypto.core.Aes128.initEnc(key);
    var plaintext = try std.ArrayList(u8).initCapacity(std.heap.page_allocator, ciphertext.len);
    errdefer plaintext.deinit();

    var counter: [16]u8 = iv;
    var i: usize = 0;
    while (i < ciphertext.len) {
        const keystream = cipher.encrypt(counter);
        crypto.utils.xorBlocks(keystream[0..], ciphertext[i..][0..16], keystream[0..]);
        plaintext.appendSliceAssumeCapacity(keystream[0..]);
        crypto.utils.incrementCounter(&counter);
        i += 16;
    }

    return plaintext.toOwnedSlice();
}