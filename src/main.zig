const std = @import("std");
const cf = @import("cf");

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

const JasminFile = struct {
    source: []const u8,
    accessor: cf.AccessFlags,
    class_name: []const u8,
    super_accessor: cf.AccessFlags,
    super_class_name: []const u8,
    interfaces: [][]const u8,
    fields: []Field,
    methods: []Method,
};

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
    name: []const u8,
};
const Method = struct {
    name: []const u8,
};

const Parser = struct {
    allocator: std.mem.Allocator,
    source: ?[]const u8 = null,
    class_name: ?ClassName = null,
    super_class_name: ?ClassName = null,
    interfaces: std.ArrayListUnmanaged(Interface),
    fields: std.ArrayListUnmanaged(Field),
    methods: std.ArrayListUnmanaged(Method),

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
        self.methods.clearAndFree(self.allocator);
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
                        std.log.err("Found {s}", .{tok});
                        return error.InvalidFile;
                    },
                }
            }
        }
    }

    pub fn parseDirective(self: *Parser, tok: []const u8, tok_iter: *std.mem.TokenIterator(u8)) !void {
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
            else => {
                std.debug.print("TODO: Unimplemented", .{});
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

const Label = struct {
    name: []const u8,
    pub fn decode(allocator: std.mem.Allocator, reader: anytype) !Label {
        const token = try reader.readUntilDelimiterAlloc(allocator, '\n', 1024);
        const name = std.mem.sliceTo(token, ':');
        if (name.len >= token.len) return error.MissingColon;
        return Label{
            .name = name,
        };
    }
    pub fn deinit(self: Label, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
    }
};

const Instructions = enum {
    // local variables
    ret,
    aload,
    astore,
    dload,
    dstore,
    fload,
    fstore,
    iload,
    istore,
    lload,
    lstore,

    bipush,
    sipish,
    iinc,

    // branching
    goto,
    goto_w,
    if_acmpeq,
    if_acmpne,
    if_icmpeq,
    if_icmpge,
    if_icmpgt,
    if_icmple,
    if_icmplt,
    if_icmpne,
    ifeq,
    ifge,
    ifgt,
    ifle,
    iflt,
    ifne,
    ifnonnull,
    ifnull,
    jsr,
    jsr_w,

    // classes and objects
    anewarray,
    checkcast,
    instanceof,
    new,

    // method invocation
    invokenonvirtual,
    invokestatic,
    invokevirtual,
    invokeinterface,

    // field manipulation
    getfield,
    getstatic,
    putfield,
    putstatic,

    newarray,
    multinewarray,

    ldc,
    ldc_w,

    lookupswitch,
    tableswitch,

    // Instructions with no parameters
    aaload,
    aastore,
    aconst_null,
    aload_0,
    aload_1,
    aload_2,
    aload_3,
    areturn,
    arraylength,
    astore_0,
    astore_1,
    astore_2,
    astore_3,
    athrow,
    baload,
    bastore,
    breakpoint,
    caload,
    castore,
    d2f,
    d2i,
    d2l,
    dadd,
    daload,
    dastore,
    dcmpg,
    dcmpl,
    dconst_0,
    dconst_1,
    ddiv,
    dload_0,
    dload_1,
    dload_2,
    dload_3,
    dmul,
    dneg,
    drem,
    dreturn,
    dstore_0,
    dstore_1,
    dstore_2,
    dstore_3,
    dsub,
    dup,
    dup2,
    dup2_x1,
    dup2_x2,
    dup_x1,
    dup_x2,
    f2d,
    f2i,
    f2l,
    fadd,
    faload,
    fastore,
    fcmpg,
    fcmpl,
    fconst_0,
    fconst_1,
    fconst_2,
    fdiv,
    fload_0,
    fload_1,
    fload_2,
    fload_3,
    fmul,
    fneg,
    frem,
    freturn,
    fstore_0,
    fstore_1,
    fstore_2,
    fstore_3,
    fsub,
    i2d,
    i2f,
    i2l,
    iadd,
    iaload,
    iand,
    iastore,
    iconst_0,
    iconst_1,
    iconst_2,
    iconst_3,
    iconst_4,
    iconst_5,
    iconst_m1,
    idiv,
    iload_0,
    iload_1,
    iload_2,
    iload_3,
    imul,
    ineg,
    int2byte,
    int2char,
    int2short,
    ior,
    irem,
    ireturn,
    ishl,
    ishr,
    istore_0,
    istore_1,
    istore_2,
    istore_3,
    isub,
    iushr,
    ixor,
    l2d,
    l2f,
    l2i,
    ladd,
    laload,
    land,
    lastore,
    lcmp,
    lconst_0,
    lconst_1,
    ldiv,
    lload_0,
    lload_1,
    lload_2,
    lload_3,
    lmul,
    lneg,
    lor,
    lrem,
    lreturn,
    lshl,
    lshr,
    lstore_0,
    lstore_1,
    lstore_2,
    lstore_3,
    lsub,
    lushr,
    lxor,
    monitorenter,
    monitorexit,
    nop,
    pop,
    pop2,
    @"return",
    saload,
    sastore,
    swap,
};
