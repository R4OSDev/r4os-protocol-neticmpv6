const std = @import("std");
const sdk = @import("r4os");
const a = sdk.abi;
const wire = @import("wire.zig");

comptime {
    asm (sdk.technical2.protocolEntriesAsm("icmp6_init", "icmp6_shutdown", "icmp6_query", "icmp6_dispatch"));
}
export fn icmp6_init(api: *const a.ProtocolApi2) callconv(.c) i32 {
    const view = sdk.technical2.Protocol.init(api) orelse return a.network_error_backend;
    const register = view.function("register_role") orelse return a.err_no_fn;
    const status = view.function("set_status") orelse return a.err_no_fn;
    if (register("net.icmpv6", @intFromEnum(a.ProtocolCategory.net), 0) != 0) return a.network_error_backend;
    return status(@intFromEnum(a.ProtocolState.active), "ICMPv6 wire codec; no transport capability implied");
}
export fn icmp6_shutdown() callconv(.c) i32 {
    return 0;
}
export fn icmp6_query(out: *a.ProtocolStatus) callconv(.c) i32 {
    out.* = .{ .state = @intFromEnum(a.ProtocolState.active) };
    const text = "Bounded ICMPv6 and IPv6 pseudoheader codec";
    @memcpy(out.note[0..text.len], text);
    return 0;
}
fn failure(err: wire.Error) i32 {
    return switch (err) {
        error.Capacity => a.network_error_capacity,
        error.NoReply => a.network_error_unsupported_policy,
        else => a.network_error_invalid,
    };
}
export fn icmp6_dispatch(op: u32, input: *const a.ProtocolBuffer, output: *a.ProtocolBuffer) callconv(.c) i32 {
    if (input.flags != 0 or input.reserved != 0 or input.len > input.capacity or output.flags != 0 or output.reserved != 0) return a.network_error_invalid;
    if (input.data == null or input.len != @sizeOf(a.Icmpv6Message) or output.data == null or output.capacity < @sizeOf(a.Icmpv6Message)) return a.network_error_invalid;
    var request: a.Icmpv6Message = undefined;
    const raw: [*]const u8 = @ptrCast(input.data.?);
    @memcpy(std.mem.asBytes(&request), raw[0..@sizeOf(a.Icmpv6Message)]);
    if (request.version != 1 or request.size != @sizeOf(a.Icmpv6Message) or request.bytes > wire.max_message or request.checksum != 0 or !std.mem.allEqual(u8, request.payload[request.bytes..], 0)) return a.network_error_invalid;
    if (request.next_header > 255 or (op != a.icmpv6_op_checksum and request.next_header != 58)) return a.network_error_unsupported_policy;
    if (op != a.icmpv6_op_error and request.flags != 0 or request.flags & ~@as(u32, 7) != 0) return a.network_error_invalid;
    if (op != a.icmpv6_op_echo_reply and !wire.unspecified(request.reply_source)) return a.network_error_invalid;
    var result = request;
    const bytes = request.payload[0..request.bytes];
    switch (op) {
        a.icmpv6_op_parse => {
            _ = wire.parse(request.source, request.destination, bytes) catch |err| return failure(err);
        },
        a.icmpv6_op_checksum => result.checksum = wire.checksumNext(request.source, request.destination, @intCast(request.next_header), bytes),
        a.icmpv6_op_seal => wire.seal(request.source, request.destination, 58, result.payload[0..result.bytes]) catch |err| return failure(err),
        a.icmpv6_op_echo_reply => {
            const source = if (wire.unspecified(request.reply_source)) request.destination else request.reply_source;
            result.bytes = @intCast(wire.echoReply(request.source, request.destination, source, bytes, &result.payload) catch |err| return failure(err));
            result.source = source;
            result.destination = request.source;
            result.reply_source = .{0} ** 16;
        },
        a.icmpv6_op_error => {
            if (request.bytes < 48 or request.payload[2] != 0 or request.payload[3] != 0) return a.network_error_invalid;
            const word = std.mem.readInt(u32, request.payload[4..8], .big);
            result.bytes = @intCast(wire.errorMessage(request.payload[0], request.payload[1], word, request.source, request.destination, bytes[8..], .{
                .multicast_exception = request.flags & 1 != 0,
                .invoking_error = request.flags & 2 != 0,
                .non_initial_fragment = request.flags & 4 != 0,
            }, &result.payload) catch |err| return failure(err));
            result.flags = 0;
        },
        else => return a.network_error_unsupported_policy,
    }
    @memset(result.payload[result.bytes..], 0);
    const destination: [*]u8 = @ptrCast(output.data.?);
    @memcpy(destination[0..@sizeOf(a.Icmpv6Message)], std.mem.asBytes(&result));
    output.len = @sizeOf(a.Icmpv6Message);
    return 0;
}
