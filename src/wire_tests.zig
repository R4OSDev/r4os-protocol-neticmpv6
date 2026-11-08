const std = @import("std");
const wire = @import("wire.zig");
fn loopback() wire.Address {
    var out: wire.Address = .{0} ** 16;
    out[15] = 1;
    return out;
}
const request = [_]u8{ 0x80, 0, 0x9b, 0x72, 0x43, 0x21, 0x5a, 0x5a, 'o', 'd', 'd', '-', 'R', '4', '!' };
const reply = [_]u8{ 0x81, 0, 0x9a, 0x72, 0x43, 0x21, 0x5a, 0x5a, 'o', 'd', 'd', '-', 'R', '4', '!' };

test "independent Linux IPv6 loopback kernel request and reply with odd payload" {
    const source = loopback();
    try std.testing.expectEqual(@as(u16, 0), wire.checksum(source, source, &request));
    try std.testing.expectEqual(@as(u16, 0), wire.checksum(source, source, &reply));
    try std.testing.expectEqual(@as(u8, 128), (try wire.parse(source, source, &request)).kind);
    var output: [40]u8 = .{0xa5} ** 40;
    try std.testing.expectEqual(request.len, try wire.echoReply(source, source, source, &request, &output));
    try std.testing.expectEqualSlices(u8, &reply, output[0..reply.len]);
    try std.testing.expect(std.mem.allEqual(u8, output[reply.len..], 0xa5));
}
test "pseudoheader binds source destination protocol length and every payload byte" {
    const source = loopback();
    var other = source;
    other[15] = 2;
    try std.testing.expectError(error.Checksum, wire.parse(other, source, &request));
    try std.testing.expectError(error.Checksum, wire.parse(source, other, &request));
    try std.testing.expect(wire.checksumNext(source, source, 17, &request) != 0);
    try std.testing.expectError(error.Checksum, wire.parse(source, source, request[0 .. request.len - 1]));
    var changed = request;
    changed[14] ^= 1;
    try std.testing.expectError(error.Checksum, wire.parse(source, source, &changed));
    // Independent Python network-order ones-complement vector for the whole
    // public1504-byte buffer, including the last four bytes after byte1500.
    var whole: [1504]u8 = undefined;
    for (&whole, 0..) |*byte, i| byte.* = @intCast(i % 251);
    try std.testing.expectEqual(@as(u16, 0xd5e9), wire.checksumNext(source, source, 17, &whole));
    whole[1503] ^= 1;
    try std.testing.expect(wire.checksumNext(source, source, 17, &whole) != 0xd5e9);
}
test "short malformed and capacity replies preserve caller output" {
    const source = loopback();
    var output: [40]u8 = .{0xa5} ** 40;
    try std.testing.expectError(error.Short, wire.echoReply(source, source, source, request[0..3], &output));
    try std.testing.expectError(error.Capacity, wire.echoReply(source, source, source, &request, output[0..4]));
    var bad = request;
    bad[1] = 1;
    try wire.seal(source, source, 58, &bad);
    try std.testing.expectError(error.Malformed, wire.echoReply(source, source, source, &bad, &output));
    try std.testing.expect(std.mem.allEqual(u8, &output, 0xa5));
}
test "ND minimum lengths and unknown informational codes remain distinct" {
    const source = loopback();
    var message: [40]u8 = .{0} ** 40;
    for ([_]struct { kind: u8, minimum: usize }{ .{ .kind = 133, .minimum = 8 }, .{ .kind = 134, .minimum = 16 }, .{ .kind = 135, .minimum = 24 }, .{ .kind = 136, .minimum = 24 }, .{ .kind = 137, .minimum = 40 } }) |item| {
        message[0] = item.kind;
        try wire.seal(source, source, 58, message[0 .. item.minimum - 1]);
        try std.testing.expectError(error.Short, wire.parse(source, source, message[0 .. item.minimum - 1]));
        try wire.seal(source, source, 58, message[0..item.minimum]);
        _ = try wire.parse(source, source, message[0..item.minimum]);
    }
    message[0] = 220;
    message[1] = 255;
    try wire.seal(source, source, 58, message[0..4]);
    try std.testing.expectEqual(@as(u8, 220), (try wire.parse(source, source, message[0..4])).kind);
}
test "error quoting stays within minimum IPv6 MTU and carries real checksum" {
    const source = loopback();
    var destination = source;
    destination[15] = 2;
    var quote: [1500]u8 = .{0x61} ** 1500;
    quote[0] = 0x60;
    @memcpy(quote[8..24], &destination);
    @memcpy(quote[24..40], &source);
    var output: [1500]u8 = .{0xa5} ** 1500;
    const length = try wire.errorMessage(2, 0, 1280, source, destination, &quote, .{}, &output);
    try std.testing.expectEqual(@as(usize, 1240), length);
    try std.testing.expectEqual(@as(u32, 1280), std.mem.readInt(u32, output[4..8], .big));
    try std.testing.expectEqualSlices(u8, quote[0..1232], output[8..length]);
    _ = try wire.parse(source, destination, output[0..length]);
    try std.testing.expect(std.mem.allEqual(u8, output[length..], 0xa5));
}
test "ICMP errors never answer errors noninitial fragments or disallowed multicast" {
    const source = loopback();
    var destination = source;
    destination[15] = 2;
    var quote: [48]u8 = .{0} ** 48;
    quote[0] = 0x60;
    @memcpy(quote[8..24], &destination);
    @memcpy(quote[24..40], &source);
    var out: [80]u8 = .{0xa5} ** 80;
    try std.testing.expectError(error.NoReply, wire.errorMessage(1, 0, 0, source, destination, &quote, .{ .invoking_error = true }, &out));
    try std.testing.expectError(error.NoReply, wire.errorMessage(1, 0, 0, source, destination, &quote, .{ .non_initial_fragment = true }, &out));
    quote[24] = 0xff;
    try std.testing.expectError(error.NoReply, wire.errorMessage(1, 0, 0, source, destination, &quote, .{}, &out));
    try std.testing.expectError(error.NoReply, wire.errorMessage(1, 0, 0, source, destination, &quote, .{ .multicast_exception = true }, &out));
    try std.testing.expect(std.mem.allEqual(u8, &out, 0xa5));
    _ = try wire.errorMessage(2, 0, 1280, source, destination, &quote, .{ .multicast_exception = true }, &out);
}
