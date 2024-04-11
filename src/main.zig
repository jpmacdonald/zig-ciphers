const caesar = @import("ciphers/classical/caesar.zig");

pub fn main() !void {
    const plaintext = "Hello, World!";
    const shift: u8 = 3;

    const ciphertext = try caesar.encrypt(plaintext, shift);
    std.debug.print("Ciphertext: {s}\n", .{ciphertext});

    const decrypted = try caesar.decrypt(ciphertext, shift);
    std.debug.print("Decrypted: {s}\n", .{decrypted});
}