const std = @import("std");

pub fn tokenize(allocator: std.mem.Allocator, buffer: []const u8) !std.MultiArrayList(Token) {
    var tokens = std.MultiArrayList(Token){};

    var line_iter = std.mem.tokenize(u8, buffer, "\n");

    while (line_iter.next()) |line| {
        try tokenizeLine(allocator, line_iter.index, line, &tokens);
    }

    return tokens;
}

pub fn tokenizeLine(allocator: std.mem.Allocator, where: usize, line: []const u8, tokens: *std.MultiArrayList(Token)) !void {
    var tok_iter = std.mem.tokenize(u8, line, "\t ");
    while (tok_iter.next()) |tok| {
        if (tok[0] == '.') {
            try tokens.append(allocator, .{
                .type = .directive,
                .start = where + tok_iter.index,
            });
        } else if (tok[0] == ';') {
            try tokens.append(allocator, .{
                .type = .comment,
                .start = where + tok_iter.index,
            });
            return; // No more tokens can be found on this line
        } else if (tok[tok.len - 1] == ':') {
            try tokens.append(allocator, .{
                .type = .label,
                .start = where + tok_iter.index,
            });
        } else if (isAccessor()) {
            try tokens.append(allocator, .{
                .type = .accessor,
                .start = where + tok_iter.index,
            });
        }
    }
}

const DirectiveType = enum {
    @"catch",
    class,
    end,
    field,
    implements,
    interface,
    limit,
    line,
    method,
    source,
    super,
    throws,
    @"var",
};

test "tokenize" {
    const test_bytes =
        \\.source MyClass.j
        \\.class public MyClass
        \\.super java/lang/Object
    ;
    var tokens = try tokenize(std.testing.allocator, test_bytes);
    defer tokens.deinit(std.testing.allocator);
    try std.testing.expectEqual(Token.Type.directive, tokens.get(0).type);
    try std.testing.expectEqual(Token.Type.identifier, tokens.get(1).type);

    try std.testing.expectEqual(Token.Type.directive, tokens.get(2).type);
    try std.testing.expectEqual(Token.Type.accessor, tokens.get(3).type);
    try std.testing.expectEqual(Token.Type.identifier, tokens.get(4).type);

    try std.testing.expectEqual(Token.Type.directive, tokens.get(5).type);
    try std.testing.expectEqual(Token.Type.identifier, tokens.get(5).type);
}

const Token = struct {
    type: Type,
    start: usize,
    const Type = enum {
        comment,
        directive,
        identifier,
        label,
        number,
        string,
        class_name,
        descriptor,
        method,
        field,
    };
};
