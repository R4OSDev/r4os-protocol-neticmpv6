//! Bounded ICMPv6 wire primitives. Address selection, routing, ND state and
//! error rate policy belong to their respective external protocol owners.
const std = @import("std");
const cursor = @import("r4os").binary_cursor;
const Checksum16 = @import("r4os").internet_checksum.Checksum16;
pub const Address = [16]u8;
pub const max_message = 1504;
pub const max_sent_message = 1240; // IPv6 minimum MTU1280 minus its40byte header.
pub const Error = error{ Short, Capacity, Checksum, Malformed, NoReply };
pub const View = struct { kind: u8, code: u8, bytes: []const u8 };

/// This same pure pseudoheader primitive can serve other upper layers;
/// its existence does not advertise any TCP/UDP transport capability.
pub fn checksumNext(source: Address, destination: Address, next: u8, bytes: []const u8) u16 {
    std.debug.assert(bytes.len <= max_message);
    // The protocol retains IPv6 pseudoheader composition and the raw zero
    // result. The shared streaming sum supplies carries and odd-byte handling.
    var header: [8]u8 = @splat(0);
    var writer = cursor.Writer.init(&header) catch unreachable;
    writer.writeInt(u32, @intCast(bytes.len), .big) catch unreachable;
    writer.position = 7;
    writer.writeInt(u8, next, .big) catch unreachable;
    var sum: Checksum16 = .{};
    sum.add(&source) catch unreachable;
    sum.add(&destination) catch unreachable;
    sum.add(&header) catch unreachable;
    sum.add(bytes) catch unreachable;
    return sum.finish() catch unreachable;
}
pub fn checksum(source: Address, destination: Address, bytes: []const u8) u16 {
    return checksumNext(source, destination, 58, bytes);
}
pub fn unspecified(address: Address) bool {
    return std.mem.allEqual(u8, &address, 0);
}
pub fn multicast(address: Address) bool {
    return address[0] == 0xff;
}
pub fn linkLocal(address: Address) bool {
    return address[0] == 0xfe and address[1] & 0xc0 == 0x80;
}
fn codeValid(kind: u8, code: u8) bool {
    return switch (kind) {
        1 => code <= 6,
        2 => code == 0,
        3 => code <= 1,
        4 => code <= 3,
        128, 129, 133...137 => code == 0,
        else => true, // Unknown informational types are ignored by the owner.
    };
}
pub fn parse(source: Address, destination: Address, bytes: []const u8) Error!View {
    if (bytes.len < 4) return error.Short;
    if (bytes.len > max_message) return error.Capacity;
    if (checksum(source, destination, bytes) != 0) return error.Checksum;
    if (!codeValid(bytes[0], bytes[1])) return error.Malformed;
    const minimum: usize = switch (bytes[0]) {
        1...4, 128, 129, 133 => 8,
        134 => 16,
        135, 136 => 24,
        137 => 40,
        else => 4,
    };
    if (bytes.len < minimum) return error.Short;
    return .{ .kind = bytes[0], .code = bytes[1], .bytes = bytes };
}
/// Callers prepare a private copied message before sealing; no caller output
/// is changed on a length error. The source/destination bytes are explicit.
pub fn seal(source: Address, destination: Address, next: u8, bytes: []u8) Error!void {
    if (bytes.len < 4) return error.Short;
    if (bytes.len > max_message) return error.Capacity;
    bytes[2] = 0;
    bytes[3] = 0;
    const value = checksumNext(source, destination, next, bytes);
    bytes[2] = @truncate(value >> 8);
    bytes[3] = @truncate(value);
}
pub fn echoReply(source: Address, destination: Address, reply_source: Address, bytes: []const u8, out: []u8) Error!usize {
    const view = try parse(source, destination, bytes);
    if (view.kind != 128 or view.code != 0) return error.Malformed;
    if (unspecified(source) or multicast(source) or unspecified(reply_source) or multicast(reply_source)) return error.NoReply;
    if (bytes.len > max_sent_message or out.len < bytes.len) return error.Capacity;
    var private: [max_sent_message]u8 = undefined;
    @memcpy(private[0..bytes.len], bytes);
    private[0] = 129;
    try seal(reply_source, source, 58, private[0..bytes.len]);
    @memcpy(out[0..bytes.len], private[0..bytes.len]);
    return bytes.len;
}
pub const ErrorPolicy = struct {
    multicast_exception: bool = false,
    invoking_error: bool = false,
    non_initial_fragment: bool = false,
};
/// The IPv6 parser supplies extension/fragment and option-action facts. This
/// codec never guesses them from an unparsed quoted payload.
pub fn errorMessage(kind: u8, code: u8, word: u32, source: Address, destination: Address, quoted: []const u8, policy: ErrorPolicy, out: []u8) Error!usize {
    if (kind < 1 or kind > 4 or !codeValid(kind, code)) return error.Malformed;
    if ((kind == 1 or kind == 3) and word != 0) return error.Malformed;
    if (quoted.len < 40 or quoted[0] >> 4 != 6) return error.Short;
    const original_source: Address = quoted[8..24].*;
    const original_dest: Address = quoted[24..40].*;
    if (unspecified(source) or multicast(source) or unspecified(original_source) or multicast(original_source) or
        !std.mem.eql(u8, &destination, &original_source) or policy.invoking_error or policy.non_initial_fragment or
        multicast(original_dest) and !(kind == 2 or kind == 4 and code == 2 and policy.multicast_exception)) return error.NoReply;
    const count = @min(quoted.len, max_sent_message - 8);
    if (out.len < count + 8) return error.Capacity;
    var private: [max_sent_message]u8 = .{0} ** max_sent_message;
    private[0] = kind;
    private[1] = code;
    var writer = cursor.Writer.init(private[4..8]) catch unreachable;
    writer.writeInt(u32, word, .big) catch unreachable;
    @memcpy(private[8..][0..count], quoted[0..count]);
    try seal(source, destination, 58, private[0 .. count + 8]);
    @memcpy(out[0 .. count + 8], private[0 .. count + 8]);
    return count + 8;
}
