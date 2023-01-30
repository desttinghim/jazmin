const std = @import("std");
const cf = @import("cf");
const Instruction = @import("instruction.zig").Instruction;
const InstructionType = @import("instruction.zig").InstructionType;

pub fn main() !void {
    // Prints to stderr (it's a shortcut based on `std.io.getStdErr()`)
    std.debug.print("All your {s} are belong to us.\n", .{"codebase"});

    // stdout is for the actual output of your application, for example if you
    // are implementing gzip, then only the compressed bytes should be sent to
    // stdout, not any debugging messages.
    const stdout_file = std.io.getStdOut().writer();
    var bw = std.io.bufferedWriter(stdout_file);
    const stdout = bw.writer();

    try stdout.print("Run `zig build test` to run the tests.\n", .{});

    try bw.flush(); // don't forget to flush!

    // var class = cf.ClassFile{
    //     .major_version = 0,
    //     .minor_version = 0,
    //     .constant_pool = 0,
    //     .constant_pool = try cf.ConstantPool.init(allocator, entry_count),
    // };
    // _ = class;
}

const ClassName = struct {
    accessor: cf.ClassFile.AccessFlags,
    token: []const u8,

    pub fn parse(token_iterator: *std.mem.TokenIterator(u8)) !ClassName {
        var access = cf.ClassFile.AccessFlags{};
        var next = token_iterator.next();
        while (next) |tok| : (next = token_iterator.next()) {
            if (std.mem.eql(u8, tok, "public")) {
                access.public = true;
            } else if (std.mem.eql(u8, tok, "final")) {
                access.final = true;
            } else if (std.mem.eql(u8, tok, "super")) {
                access.super = true;
            } else if (std.mem.eql(u8, tok, "interface")) {
                access.interface = true;
            } else if (std.mem.eql(u8, tok, "abstract")) {
                access.abstract = true;
            } else {
                break;
            }
        }
        return ClassName{
            .accessor = access,
            .token = next orelse return error.UnexpectedEnd,
        };
    }
};

const Interface = struct {
    name: []const u8,
};
const Field = struct {
    accessor: cf.FieldInfo.AccessFlags,
    name: []const u8,
    descriptor: []const u8,
    value: ?[]const u8,
    pub fn parse(token_iterator: *std.mem.TokenIterator(u8)) !Field {
        var access = cf.FieldInfo.AccessFlags{};
        var next = token_iterator.next();
        while (next) |tok| : (next = token_iterator.next()) {
            if (std.mem.eql(u8, tok, "public")) {
                access.public = true;
            } else if (std.mem.eql(u8, tok, "private")) {
                access.private = true;
            } else if (std.mem.eql(u8, tok, "protected")) {
                access.protected = true;
            } else if (std.mem.eql(u8, tok, "static")) {
                access.static = true;
            } else if (std.mem.eql(u8, tok, "final")) {
                access.final = true;
            } else if (std.mem.eql(u8, tok, "volatile")) {
                access.@"volatile" = true;
            } else if (std.mem.eql(u8, tok, "transient")) {
                access.transient = true;
            } else {
                break;
            }
        }
        var name = next orelse return error.UnexpectedEnd;
        var descriptor = token_iterator.next() orelse return error.UnexpectedEnd;
        var value: ?[]const u8 = if (token_iterator.peek()) |tok| value: {
            if (!std.mem.eql(u8, tok, "=")) {
                break :value null;
            }
            _ = token_iterator.next(); // skip the "="
            break :value token_iterator.next();
        } else null;
        return Field{
            .accessor = access,
            .name = name,
            .descriptor = descriptor,
            .value = value,
        };
    }
};
const Method = struct {
    accessor: cf.MethodInfo.AccessFlags,
    name: []const u8,
    stack_limit: ?u16 = null,
    instructions: std.ArrayListUnmanaged(Instruction),
    labels: std.StringHashMapUnmanaged(usize),
    pub fn parse(token_iterator: *std.mem.TokenIterator(u8)) !Method {
        var access = cf.MethodInfo.AccessFlags{};
        var next = token_iterator.next();
        while (next) |tok| : (next = token_iterator.next()) {
            if (std.mem.eql(u8, tok, "public")) {
                access.public = true;
            } else if (std.mem.eql(u8, tok, "private")) {
                access.private = true;
            } else if (std.mem.eql(u8, tok, "protected")) {
                access.protected = true;
            } else if (std.mem.eql(u8, tok, "static")) {
                access.static = true;
            } else if (std.mem.eql(u8, tok, "final")) {
                access.final = true;
            } else if (std.mem.eql(u8, tok, "synchronized")) {
                access.synchronized = true;
            } else if (std.mem.eql(u8, tok, "native")) {
                access.native = true;
            } else if (std.mem.eql(u8, tok, "abstract")) {
                access.abstract = true;
            } else {
                break;
            }
        }
        var name = next orelse return error.UnexpectedEnd;
        return Method{
            .accessor = access,
            .name = name,
            .instructions = std.ArrayListUnmanaged(Instruction){},
            .labels = std.StringHashMapUnmanaged(usize){},
        };
    }
    pub fn deinit(self: *Method, allocator: std.mem.Allocator) void {
        self.instructions.clearAndFree(allocator);
        self.labels.clearAndFree(allocator);
    }
};

fn tokenizeString(tok_iter: *std.mem.TokenIterator(u8)) ?[]const u8 {
    var tok = tok_iter.peek() orelse return null;
    if (tok[0] != '"') return null;
    var new_slice = std.mem.sliceTo(tok_iter.buffer[tok_iter.index + 1 ..], '"');
    tok_iter.index += new_slice.len + 2;
    return new_slice;
}

const Parser = struct {
    has_parsed: bool,
    allocator: std.mem.Allocator,
    source: ?[]const u8 = null,
    class_name: ?ClassName = null,
    super_class_name: ?ClassName = null,
    interfaces: std.ArrayListUnmanaged(Interface),
    fields: std.ArrayListUnmanaged(Field),
    methods: std.ArrayListUnmanaged(Method),
    is_parsing_method: bool = false,

    pub fn init(allocator: std.mem.Allocator) Parser {
        return Parser{
            .allocator = allocator,
            .interfaces = std.ArrayListUnmanaged(Interface){},
            .fields = std.ArrayListUnmanaged(Field){},
            .methods = std.ArrayListUnmanaged(Method){},
        };
    }

    pub fn deinit(self: *Parser) void {
        self.interfaces.clearAndFree(self.allocator);
        self.fields.clearAndFree(self.allocator);
        for (self.methods.items) |*method| {
            method.deinit(self.allocator);
        }
        self.methods.clearAndFree(self.allocator);
    }

    pub fn setSource(self: *Parser, name: []const u8) void {
        self.source = name;
    }

    pub fn parse(self: *Parser, buffer: []const u8) !void {
        var line_iter = std.mem.tokenize(u8, buffer, "\n");

        while (line_iter.next()) |line| line: {
            var tok_iter = std.mem.tokenize(u8, line, "\t ");
            while (tok_iter.next()) |tok| {
                switch (tok[0]) {
                    ';' => break :line, // Line is a comment, stop processing
                    '.' => try self.parseDirective(tok, &tok_iter),
                    else => {
                        if (tok[tok.len - 1] == ':' and self.is_parsing_method) {
                            std.log.info("Found label {s}", .{tok});
                            // TODO
                        } else if (std.meta.stringToEnum(InstructionType, tok)) |instruction| {
                            std.log.info("Found instruction {}", .{instruction});
                            try self.parseInstruction(instruction, &tok_iter);
                        } else {
                            std.log.err("Found {s}", .{tok});
                            return error.InvalidFile;
                        }
                    },
                }
            }
        }
        self.has_parsed = true;
    }

    fn parseDirective(self: *Parser, tok: []const u8, tok_iter: *std.mem.TokenIterator(u8)) !void {
        var directive_type = std.meta.stringToEnum(DirectiveType, tok[1..]) orelse return error.InvalidDirective;
        switch (directive_type) {
            .source => {
                self.source = tok_iter.next() orelse return error.UnexpectedEnd;
            },
            .interface => {
                self.class_name = try ClassName.parse(tok_iter);
                self.class_name.?.accessor.interface = true;
            },
            .class => {
                self.class_name = try ClassName.parse(tok_iter);
            },
            .super => {
                self.super_class_name = try ClassName.parse(tok_iter);
            },
            .implements => {
                try self.interfaces.append(self.allocator, .{
                    .name = tok_iter.next() orelse return error.UnexpectedEnd,
                });
            },
            .field => {
                try self.fields.append(self.allocator, try Field.parse(tok_iter));
            },
            .method => {
                try self.methods.append(self.allocator, try Method.parse(tok_iter));
                self.is_parsing_method = true;
            },
            .end => {
                var end_what = tok_iter.next() orelse return error.UnexpectedEnd;
                std.debug.assert(std.mem.eql(u8, end_what, "method")); // TODO: is .end used for anything other than methods?
                self.is_parsing_method = false;
            },
            inline .limit, .line, .@"var", .throws, .@"catch" => |method_directive| {
                if (!self.is_parsing_method) {
                    std.debug.print("Method directive used outside of method declaration\n", .{});
                    return error.UnexpectedMethodDirective;
                }
                std.debug.assert(self.methods.items.len > 0);
                const method = &self.methods.items[self.methods.items.len - 1];
                switch (method_directive) {
                    .limit => {
                        const what = tok_iter.next() orelse return error.UnexpectedEnd;
                        const limit = tok_iter.next() orelse return error.UnexpectedEnd;
                        std.debug.print("{s} limit set to {s}\n", .{ what, limit });
                        // TODO: is the stack limit part of the class file?
                        std.debug.assert(std.mem.eql(u8, what, "stack"));
                        method.stack_limit = try std.fmt.parseInt(u16, limit, 10);
                    },
                    .line,
                    .@"var",
                    .throws,
                    .@"catch",
                    => {
                        std.debug.print("TODO: Unimplemented\n", .{});
                    },
                    inline else => @compileError("Switch on method directives produced non-method directive"),
                }
            },
        }
    }

    fn parseInstruction(self: *Parser, instruction: InstructionType, tok_iter: *std.mem.TokenIterator(u8)) !void {
        std.debug.assert(self.methods.items.len > 0);
        const method = &self.methods.items[self.methods.items.len - 1];
        switch (instruction) {
            .invokeinterface => {
                const method_name = tok_iter.next() orelse return error.UnexpectedEnd;
                const index_str = tok_iter.next() orelse return error.UnexpectedEnd;
                const index = try std.fmt.parseInt(u8, index_str, 10);
                try method.instructions.append(self.allocator, .{ .invokeinterface = .{
                    .method_spec = method_name,
                    .arg_count = index,
                } });
            },
            .ldc => {
                const constant = tokenizeString(tok_iter) orelse tok_iter.next() orelse return error.UnexpectedEnd;
                try method.instructions.append(self.allocator, .{ .ldc = constant });
            },
            .iinc => {
                const index_str = tok_iter.next() orelse return error.UnexpectedEnd;
                const index = try std.fmt.parseInt(u8, index_str, 10);
                const int_str = tok_iter.next() orelse return error.UnexpectedEnd;
                const int = try std.fmt.parseInt(i32, int_str, 10);
                try method.instructions.append(self.allocator, .{ .iinc = .{
                    .var_num = index,
                    .amount = int,
                } });
            },
            .multinewarray => {
                const descriptor = tok_iter.next() orelse return error.UnexpectedEnd;
                const index_str = tok_iter.next() orelse return error.UnexpectedEnd;
                const index = try std.fmt.parseInt(u8, index_str, 10);
                try method.instructions.append(self.allocator, .{ .multinewarray = .{
                    .descriptor = descriptor,
                    .num_dimensions = index,
                } });
            },
            inline .anewarray, .checkcast, .instanceof, .new, .newarray => |instr| {
                // .newarray technically takes a type and not a class, but both are strings in this case.
                // TODO: parse type passed to newarray
                const class_name = tok_iter.next() orelse return error.UnexpectedEnd;
                try method.instructions.append(self.allocator, @unionInit(Instruction, @tagName(instr), class_name));
            },
            inline .bipush, .sipush => |instr| {
                const int_str = tok_iter.next() orelse return error.UnexpectedEnd;
                const int = try std.fmt.parseInt(i32, int_str, 10);
                try method.instructions.append(self.allocator, @unionInit(Instruction, @tagName(instr), int));
            },
            inline .goto, .goto_w, .if_acmpeq, .if_acmpne, .if_icmpeq, .if_icmpge, .if_icmpgt, .if_icmple, .if_icmplt, .if_icmpne, .ifeq, .ifge, .ifgt, .ifle, .iflt, .ifne, .ifnonnull, .ifnull, .jsr, .jsr_w => |instr| {
                const label = tok_iter.next() orelse return error.UnexpectedEnd;
                try method.instructions.append(self.allocator, @unionInit(Instruction, @tagName(instr), label));
            },
            inline .getfield, .getstatic, .putfield, .putstatic => |instr| {
                const field = tok_iter.next() orelse return error.UnexpectedEnd;
                const descriptor = tok_iter.next() orelse return error.UnexpectedEnd;
                try method.instructions.append(self.allocator, @unionInit(Instruction, @tagName(instr), .{
                    .field_spec = field,
                    .descriptor = descriptor,
                }));
            },
            inline .invokenonvirtual, .invokevirtual, .invokestatic => |instr| {
                const method_name = tok_iter.next() orelse return error.UnexpectedEnd;
                try method.instructions.append(self.allocator, @unionInit(Instruction, @tagName(instr), method_name));
            },
            inline .ret, .aload, .astore, .dload, .dstore, .fload, .fstore, .iload, .istore, .lload, .lstore => |instr| {
                const index_str = tok_iter.next() orelse return error.UnexpectedEnd;
                const index = try std.fmt.parseInt(u8, index_str, 10);
                try method.instructions.append(self.allocator, @unionInit(Instruction, @tagName(instr), index));
            },
            inline else => |instr| {
                try method.instructions.append(self.allocator, @as(Instruction, instr));
            },
        }
    }
};

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

test "header" {
    const test_bytes =
        \\.source MyClass.j
        \\.class public MyClass
        \\.super java/lang/Object
    ;
    var parser = Parser.init(std.testing.allocator);
    defer parser.deinit();

    try parser.parse(test_bytes);

    try std.testing.expectEqualStrings("MyClass.j", parser.source.?);
    try std.testing.expectEqualStrings("MyClass", parser.class_name.?.token);
    try std.testing.expectEqualStrings("java/lang/Object", parser.super_class_name.?.token);
}

test "comment" {
    const test_bytes =
        \\.source MyClass.j
        \\.class public MyClass
        \\.super java/lang/Object
        \\; bleep bloop .source
        \\
    ;
    var parser = Parser.init(std.testing.allocator);
    defer parser.deinit();

    try parser.parse(test_bytes);

    try std.testing.expectEqualStrings("MyClass.j", parser.source.?);
    try std.testing.expectEqualStrings("MyClass", parser.class_name.?.token);
    try std.testing.expectEqualStrings("java/lang/Object", parser.super_class_name.?.token);
}

test "interface" {
    const test_bytes =
        \\.class foo
        \\.super java/lang/Object
        \\.implements Edible
        \\.implements java/lang/Throwable
    ;
    var parser = Parser.init(std.testing.allocator);
    defer parser.deinit();

    try parser.parse(test_bytes);

    try std.testing.expectEqualStrings("foo", parser.class_name.?.token);
    try std.testing.expectEqualStrings("java/lang/Object", parser.super_class_name.?.token);
    try std.testing.expectEqualStrings("Edible", parser.interfaces.items[0].name);
    try std.testing.expectEqualStrings("java/lang/Throwable", parser.interfaces.items[1].name);
}

test "fields" {
    const test_bytes =
        \\.class foo
        \\.super java/lang/Object
        \\.field public bar I
        \\.field public static final PI F = 3.14
    ;
    var parser = Parser.init(std.testing.allocator);
    defer parser.deinit();

    try parser.parse(test_bytes);

    try std.testing.expectEqualStrings("foo", parser.class_name.?.token);
    try std.testing.expectEqualStrings("java/lang/Object", parser.super_class_name.?.token);
    try std.testing.expectEqualStrings("bar", parser.fields.items[0].name);
    try std.testing.expectEqualStrings("PI", parser.fields.items[1].name);
}

test "methods" {
    const test_bytes =
        \\.class foo
        \\.super java/lang/Object
        \\.method abstract foo()V
        \\.end method
    ;
    var parser = Parser.init(std.testing.allocator);
    defer parser.deinit();

    try parser.parse(test_bytes);

    try std.testing.expectEqualStrings("foo", parser.class_name.?.token);
    try std.testing.expectEqualStrings("java/lang/Object", parser.super_class_name.?.token);
    try std.testing.expectEqualStrings("foo()V", parser.methods.items[0].name);
}

test "Hello World" {
    const test_bytes =
        \\.class public HelloWorld
        \\.super java/lang/Object
        \\
        \\; standard initializer (calls java.lang.Object's initializer)
        \\.method public <init>()V
        \\    aload_0
        \\    invokenonvirtual java/lang/Object/<init>()V
        \\    return
        \\.end method
        \\
        \\; main() - prints out Hello World
        \\.method public static main([Ljava/lang/String;)V
        \\    .limit stack 2  ; up to two items can be pushed
        \\    getstatic java/lang/System/out Ljava/io/PrintStream;
        \\    ldc "Hello, World!"
        \\    invokevirtual java/io/PrintStream/println(Ljava/lang/String;)V
        \\    return
        \\.end method
    ;
    var parser = Parser.init(std.testing.allocator);
    defer parser.deinit();

    try parser.parse(test_bytes);

    try std.testing.expectEqualStrings("HelloWorld", parser.class_name.?.token);
    try std.testing.expectEqualStrings("java/lang/Object", parser.super_class_name.?.token);
    try std.testing.expectEqualStrings("<init>()V", parser.methods.items[0].name);
    try std.testing.expectEqualStrings("main([Ljava/lang/String;)V", parser.methods.items[1].name);

    const init_method = parser.methods.items[0];
    try std.testing.expectEqual(@as(InstructionType, .aload_0), init_method.instructions.items[0]);
    try std.testing.expectEqual(@as(InstructionType, .invokenonvirtual), init_method.instructions.items[1]);
    try std.testing.expectEqual(@as(InstructionType, .@"return"), init_method.instructions.items[2]);

    const main_method = parser.methods.items[1];
    try std.testing.expectEqual(@as(?u16, 2), main_method.stack_limit);
    try std.testing.expectEqual(@as(InstructionType, .getstatic), main_method.instructions.items[0]);
    try std.testing.expectEqual(@as(InstructionType, .ldc), main_method.instructions.items[1]);
    try std.testing.expectEqual(@as(InstructionType, .invokevirtual), main_method.instructions.items[2]);
    try std.testing.expectEqual(@as(InstructionType, .@"return"), main_method.instructions.items[3]);
}
