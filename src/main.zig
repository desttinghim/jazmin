const std = @import("std");
const cf = @import("cf");
const Instruction = @import("instruction.zig").Instruction;
const InstructionType = @import("instruction.zig").InstructionType;

var gpa = std.heap.GeneralPurposeAllocator(.{}){};

pub fn main() !void {
    const stdout_file = std.io.getStdOut().writer();
    var bw = std.io.bufferedWriter(stdout_file);
    const stdout = bw.writer();

    const alloc = gpa.allocator();
    const args = try std.process.argsAlloc(alloc);

    if (args.len < 3) {
        try stdout.print("Missing args\nUSAGE:\njazmin <input> <output>\nEXAMPLE:\njazmin MyClass.j MyClass.class", .{});
        try bw.flush(); // don't forget to flush!
        return;
    }

    const cwd = std.fs.cwd();
    const file_in = try cwd.readFileAlloc(alloc, args[1], 1024 * 1024 * 1024 * 1024);
    defer alloc.free(file_in);

    var parser = Parser.init(alloc);
    defer parser.deinit();

    try parser.parse(file_in);
    var source_name = std.fs.path.basename(args[1]);
    parser.setSource(source_name);

    var class_file = try parser.toClassFile(alloc);
    defer class_file.deinit();

    const file_out = try cwd.createFile(args[2], .{});
    defer file_out.close();

    try class_file.encode(file_out.writer());
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
    local_limit: ?u16 = null,
    instructions: std.ArrayListUnmanaged(Instruction),
    labels: std.StringHashMapUnmanaged(i32),
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
            .labels = std.StringHashMapUnmanaged(i32){},
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
    allocator: std.mem.Allocator,
    source: ?[]const u8 = null,
    class_name: ?ClassName = null,
    super_class_name: ?ClassName = null,
    interfaces: std.ArrayListUnmanaged(Interface),
    fields: std.ArrayListUnmanaged(Field),
    methods: std.ArrayListUnmanaged(Method),
    is_parsing_method: bool = false,
    has_parsed: bool = false,

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

    fn addStringToConstantPool(constant_pool: *cf.ConstantPool, string: []const u8) !u16 {
        var get_or_put = try constant_pool.utf8_entries_map.getOrPut(constant_pool.allocator, string);
        const index = if (!get_or_put.found_existing) index: {
            const len = constant_pool.entries.items.len + 1;
            get_or_put.value_ptr.* = @intCast(u16, len);
            const bytes = try constant_pool.allocator.dupe(u8, string);
            try constant_pool.entries.append(constant_pool.allocator, .{ .utf8 = .{
                .constant_pool = constant_pool,
                .bytes = bytes,
            } });
            break :index @intCast(u16, len);
        } else get_or_put.value_ptr.*;
        return index;
    }

    fn addToConstantPool(constant_pool: *cf.ConstantPool, comptime T: cf.ConstantPool.Tag, data: anytype) !u16 {
        try constant_pool.entries.append(constant_pool.allocator, @unionInit(cf.ConstantPool.Entry, @tagName(T), data));
        return @intCast(u16, constant_pool.entries.items.len);
    }

    fn getMethodRef(constant_pool: *cf.ConstantPool, method_name: []const u8) !u16 {
        var paren_index = std.mem.indexOfScalar(u8, method_name, '(') orelse return error.MalformedName;
        const class_and_function = method_name[0..paren_index];
        var slash_index = std.mem.lastIndexOfScalar(u8, class_and_function, '/') orelse return error.MalformedName;
        var class = method_name[0..slash_index];
        var name = method_name[slash_index + 1 .. paren_index];
        var descriptor = method_name[paren_index..];

        var class_name_index = try addStringToConstantPool(constant_pool, class);
        var method_name_index = try addStringToConstantPool(constant_pool, name);
        var descriptor_index = try addStringToConstantPool(constant_pool, descriptor);

        var class_index_opt: ?u16 = null;
        var name_and_type_index_opt: ?u16 = null;

        for (constant_pool.entries.items) |constant, i| {
            switch (constant) {
                .class => |class_data| {
                    if (class_data.name_index == class_name_index) {
                        class_index_opt = @intCast(u16, i + 1);
                    }
                },
                .name_and_type => |name_and_type| {
                    if (name_and_type.name_index == method_name_index and name_and_type.descriptor_index == descriptor_index) {
                        name_and_type_index_opt = @intCast(u16, i + 1);
                    }
                },
                else => continue,
            }
        }

        const class_index = class_index_opt orelse class_index: {
            break :class_index try addToConstantPool(constant_pool, .class, .{
                .constant_pool = constant_pool,
                .name_index = class_name_index,
            });
        };

        const name_and_type_index = name_and_type_index_opt orelse name_and_type_index: {
            break :name_and_type_index try addToConstantPool(constant_pool, .name_and_type, .{
                .constant_pool = constant_pool,
                .name_index = method_name_index,
                .descriptor_index = descriptor_index,
            });
        };

        var ref_info_index_opt: ?u16 = null;
        for (constant_pool.entries.items) |constant, i| {
            switch (constant) {
                .methodref => |ref_info| {
                    if (ref_info.class_index == class_index and ref_info.name_and_type_index == name_and_type_index) {
                        ref_info_index_opt = @intCast(u16, i + 1);
                        break;
                    }
                },
                else => continue,
            }
        }

        const ref_info_index = ref_info_index_opt orelse ref_info_index: {
            break :ref_info_index try addToConstantPool(constant_pool, .methodref, .{
                .constant_pool = constant_pool,
                .class_index = class_index,
                .name_and_type_index = name_and_type_index,
            });
        };

        return ref_info_index;
    }

    fn getFieldRef(constant_pool: *cf.ConstantPool, field_name: []const u8, descriptor: []const u8) !u16 {
        var slash_index = std.mem.lastIndexOfScalar(u8, field_name, '/') orelse return error.MalformedName;
        var class = field_name[0..slash_index];
        var name = field_name[slash_index + 1 ..];

        var class_name_index = try addStringToConstantPool(constant_pool, class);
        var field_name_index = try addStringToConstantPool(constant_pool, name);
        var descriptor_index = try addStringToConstantPool(constant_pool, descriptor);

        var class_index_opt: ?u16 = null;
        var name_and_type_index_opt: ?u16 = null;

        for (constant_pool.entries.items) |constant, i| {
            switch (constant) {
                .class => |class_data| {
                    if (class_data.name_index == class_name_index) {
                        class_index_opt = @intCast(u16, i + 1);
                    }
                },
                .name_and_type => |name_and_type| {
                    if (name_and_type.name_index == field_name_index and name_and_type.descriptor_index == descriptor_index) {
                        name_and_type_index_opt = @intCast(u16, i + 1);
                    }
                },
                else => continue,
            }
        }

        const class_index = class_index_opt orelse class_index: {
            break :class_index try addToConstantPool(constant_pool, .class, .{
                .constant_pool = constant_pool,
                .name_index = class_name_index,
            });
        };

        const name_and_type_index = name_and_type_index_opt orelse name_and_type_index: {
            break :name_and_type_index try addToConstantPool(constant_pool, .name_and_type, .{
                .constant_pool = constant_pool,
                .name_index = field_name_index,
                .descriptor_index = descriptor_index,
            });
        };

        var ref_info_index_opt: ?u16 = null;
        for (constant_pool.entries.items) |constant, i| {
            switch (constant) {
                .fieldref => |ref_info| {
                    if (ref_info.class_index == class_index and ref_info.name_and_type_index == name_and_type_index) {
                        ref_info_index_opt = @intCast(u16, i + 1);
                        break;
                    }
                },
                else => continue,
            }
        }

        const ref_info_index = ref_info_index_opt orelse ref_info_index: {
            break :ref_info_index try addToConstantPool(constant_pool, .fieldref, .{
                .constant_pool = constant_pool,
                .class_index = class_index,
                .name_and_type_index = name_and_type_index,
            });
        };

        return ref_info_index;
    }

    fn getClassRef(constant_pool: *cf.ConstantPool, class_name: []const u8) !u16 {
        var class_name_index = try addStringToConstantPool(constant_pool, class_name);

        var class_index_opt: ?u16 = null;

        for (constant_pool.entries.items) |constant, i| {
            switch (constant) {
                .class => |class_data| {
                    if (class_data.name_index == class_name_index) {
                        class_index_opt = @intCast(u16, i);
                    }
                },
                else => continue,
            }
        }

        const class_index = class_index_opt orelse class_index: {
            break :class_index try addToConstantPool(constant_pool, .class, .{
                .constant_pool = constant_pool,
                .name_index = class_name_index,
            });
        };

        return class_index;
    }

    fn toClassFile(self: *Parser, allocator: std.mem.Allocator) !cf.ClassFile {
        if (!self.has_parsed) return error.ParsingNotComplete;

        // Initialize variables needed for ClassFile struct
        var constant_pool = try cf.ConstantPool.init(allocator, 0);
        var interfaces = std.ArrayList(u16).init(allocator);
        var fields = std.ArrayList(cf.FieldInfo).init(allocator);
        var methods = std.ArrayList(cf.MethodInfo).init(allocator);
        var attributes = std.ArrayList(cf.attributes.AttributeInfo).init(allocator);

        // add class name to constant pool
        const class_name_index = try addStringToConstantPool(constant_pool, self.class_name.?.token);
        const class_index = try addToConstantPool(constant_pool, .class, .{
            .constant_pool = constant_pool,
            .name_index = class_name_index,
        });

        // add superclass name to constant pool
        const super_class_index = if (self.super_class_name) |super_class_name| super_class: {
            const super_class_name_index = try addStringToConstantPool(constant_pool, super_class_name.token);
            const super_class_index = try addToConstantPool(constant_pool, .class, .{
                .constant_pool = constant_pool,
                .name_index = super_class_name_index,
            });
            break :super_class super_class_index;
        } else null;

        // add source to constant pool
        const source = self.source orelse return error.MissingSourceName;
        const source_index = try addStringToConstantPool(constant_pool, source);
        try attributes.append(.{ .source_file = .{
            .allocator = allocator,
            .constant_pool = constant_pool,
            .source_file_index = source_index,
        } });

        // Make sure Code and SourceFile are available as a value for the attribute to reference
        _ = try addStringToConstantPool(constant_pool, "Code");
        _ = try addStringToConstantPool(constant_pool, "SourceFile");

        // loop over interfaces and insert into the constant pool
        for (self.interfaces.items) |interface| {
            const name_index = try addStringToConstantPool(constant_pool, interface.name);
            const index = try addToConstantPool(constant_pool, .class, .{
                .constant_pool = constant_pool,
                .name_index = name_index,
            });
            try interfaces.append(index);
        }

        // loop over fields and create FieldInfo structs
        for (self.fields.items) |field| {
            const name_index = try addStringToConstantPool(constant_pool, field.name);
            const descriptor_index = try addStringToConstantPool(constant_pool, field.descriptor);
            // TODO: field attributes
            var field_attributes = std.ArrayList(cf.attributes.AttributeInfo).init(allocator);
            try fields.append(.{
                .constant_pool = constant_pool,
                .access_flags = field.accessor,
                .name_index = name_index,
                .descriptor_index = descriptor_index,
                .attributes = field_attributes,
            });
        }

        // loop over methods and create MethodInfo structs
        for (self.methods.items) |method| {
            const name_bytes = std.mem.sliceTo(method.name, '(');
            const descriptor_bytes = method.name[name_bytes.len..];
            const name_index = try addStringToConstantPool(constant_pool, name_bytes);
            const descriptor_index = try addStringToConstantPool(constant_pool, descriptor_bytes);

            // Convert bytecode
            var code = std.ArrayList(u8).init(allocator);
            const code_writer = code.writer();
            for (method.instructions.items) |instruction| {
                var operation: cf.bytecode.ops.Operation = switch (@as(InstructionType, instruction)) {
                    .bipush => .{ .bipush = instruction.bipush },
                    .sipush => .{ .sipush = instruction.sipush },
                    .iinc => .{ .iinc = .{
                        .index = instruction.iinc.var_num,
                        .@"const" = instruction.iinc.amount,
                    } },
                    inline .goto,
                    .if_acmpeq,
                    .if_acmpne,
                    .if_icmpeq,
                    .if_icmpge,
                    .if_icmpgt,
                    .if_icmple,
                    .if_icmplt,
                    .if_icmpne,
                    .ifeq,
                    .ifge,
                    .ifgt,
                    .ifle,
                    .iflt,
                    .ifne,
                    .ifnonnull,
                    .ifnull,
                    .jsr,
                    => |instr| operation: {
                        const string = @field(instruction, @tagName(instr));
                        const offset = std.fmt.parseInt(i16, string, 10) catch @intCast(i16, method.labels.get(string) orelse return error.UnknownLabel);
                        break :operation @unionInit(cf.bytecode.ops.Operation, @tagName(instr), offset);
                    },
                    inline .goto_w, .jsr_w => |instr| operation: {
                        const string = @field(instruction, @tagName(instr));
                        const offset = std.fmt.parseInt(i32, string, 10) catch method.labels.get(string) orelse return error.UnknownLabel;
                        break :operation @unionInit(cf.bytecode.ops.Operation, @tagName(instr), offset);
                    },
                    inline .aload,
                    .astore,
                    .dload,
                    .dstore,
                    .fload,
                    .fstore,
                    .iload,
                    .istore,
                    .lload,
                    .lstore,
                    => |instr| @unionInit(cf.bytecode.ops.Operation, @tagName(instr), @field(instruction, @tagName(instr))),
                    inline .anewarray,
                    .invokespecial,
                    .invokestatic,
                    .invokevirtual,
                    => |instr| operation: {
                        const ref = try getMethodRef(constant_pool, @field(instruction, @tagName(instr)));
                        break :operation @unionInit(cf.bytecode.ops.Operation, @tagName(instr), ref);
                    },
                    inline .getfield,
                    .getstatic,
                    .putstatic,
                    .putfield,
                    => |instr| operation: {
                        const field = @field(instruction, @tagName(instr));
                        const ref = try getFieldRef(constant_pool, field.field_spec, field.descriptor);
                        break :operation @unionInit(cf.bytecode.ops.Operation, @tagName(instr), ref);
                    },
                    inline .checkcast,
                    .instanceof,
                    .new,
                    => |instr| operation: {
                        const class = @field(instruction, @tagName(instr));
                        const ref = try getClassRef(constant_pool, class);
                        break :operation @unionInit(cf.bytecode.ops.Operation, @tagName(instr), ref);
                    },
                    .invokeinterface => operation: {
                        const class = try getClassRef(constant_pool, instruction.invokeinterface.method_spec);
                        break :operation .{ .invokeinterface = .{
                            .indexbyte1 = @truncate(u8, class >> 8),
                            .indexbyte2 = @truncate(u8, class),
                            .count = instruction.invokeinterface.arg_count,
                            .pad = 0,
                        } };
                    },
                    .newarray => operation: {
                        const array_type = std.meta.stringToEnum(cf.bytecode.ops.NewArrayParams, instruction.newarray) orelse return error.InvalidArrayType;
                        break :operation .{ .newarray = array_type };
                    },
                    .multianewarray => operation: {
                        const descriptor = try getClassRef(constant_pool, instruction.multianewarray.descriptor);
                        break :operation .{ .multianewarray = .{
                            .index = descriptor,
                            .dimensions = instruction.multianewarray.num_dimensions,
                        } };
                    },
                    .ldc => operation: {
                        // TODO: add constant to pool and get index
                        const utf8_constant = try addStringToConstantPool(constant_pool, instruction.ldc);
                        const string_constant = try addToConstantPool(constant_pool, .string, .{
                            .constant_pool = constant_pool,
                            .string_index = utf8_constant,
                        });
                        break :operation .{ .ldc = @intCast(u8, string_constant) };
                    },
                    .ldc_w => operation: {
                        // TODO: add constant to pool and get index
                        const constant = 0;
                        break :operation .{ .ldc_w = constant };
                    },
                    .lookupswitch, .tableswitch => unreachable,
                    inline else => |instr| operation: {
                        // @compileLog(instr);
                        break :operation @unionInit(cf.bytecode.ops.Operation, @tagName(instr), @field(instruction, @tagName(instr)));
                    },
                };
                try operation.encode(code_writer);
            }
            var exception_table = std.ArrayListUnmanaged(cf.attributes.ExceptionTableEntry){};
            var code_attributes = std.ArrayListUnmanaged(cf.attributes.AttributeInfo){};

            var code_attribute = cf.attributes.CodeAttribute{
                .allocator = allocator,
                .constant_pool = constant_pool,
                .max_stack = method.stack_limit orelse 1,
                .max_locals = method.local_limit orelse 1,
                .code = code.moveToUnmanaged(),
                .exception_table = exception_table,
                .attributes = code_attributes,
            };

            // TODO: method attributes
            var method_attributes = std.ArrayList(cf.attributes.AttributeInfo).init(allocator);
            try method_attributes.append(.{ .code = code_attribute });

            try methods.append(.{
                .constant_pool = constant_pool,
                .access_flags = method.accessor,
                .name_index = name_index,
                .descriptor_index = descriptor_index,
                .attributes = method_attributes,
            });
        }

        // TODO: add attributes?
        var class = cf.ClassFile{
            .minor_version = 0,
            .major_version = 45,
            .constant_pool = constant_pool,
            .access_flags = self.class_name.?.accessor,
            .this_class = class_index,
            .super_class = super_class_index,
            .interfaces = interfaces,
            .fields = fields,
            .methods = methods,
            .attributes = attributes,
        };
        return class;
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
                            if (!self.is_parsing_method) {
                                std.debug.print("Method directive used outside of method declaration\n", .{});
                                return error.UnexpectedMethodDirective;
                            }
                            std.debug.assert(self.methods.items.len > 0);
                            const method = &self.methods.items[self.methods.items.len - 1];
                            try method.labels.put(self.allocator, tok[0 .. tok.len - 1], @intCast(i32, method.instructions.items.len));
                        } else if (std.meta.stringToEnum(InstructionType, tok)) |instruction| {
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
                        if (std.mem.eql(u8, what, "stack")) {
                            method.stack_limit = try std.fmt.parseInt(u16, limit, 10);
                        } else if (std.mem.eql(u8, what, "local")) {
                            method.local_limit = try std.fmt.parseInt(u16, limit, 10);
                        } else {
                            return error.InvalidLimit;
                        }
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
                const index = try std.fmt.parseInt(u16, index_str, 10);
                const int_str = tok_iter.next() orelse return error.UnexpectedEnd;
                const int = try std.fmt.parseInt(i16, int_str, 10);
                try method.instructions.append(self.allocator, .{ .iinc = .{
                    .var_num = index,
                    .amount = int,
                } });
            },
            .multianewarray => {
                const descriptor = tok_iter.next() orelse return error.UnexpectedEnd;
                const dimensions_str = tok_iter.next() orelse return error.UnexpectedEnd;
                const dimensions = try std.fmt.parseInt(u8, dimensions_str, 10);
                try method.instructions.append(self.allocator, .{ .multianewarray = .{
                    .descriptor = descriptor,
                    .num_dimensions = dimensions,
                } });
            },
            .bipush => {
                const int_str = tok_iter.next() orelse return error.UnexpectedEnd;
                const int = try std.fmt.parseInt(i8, int_str, 10);
                try method.instructions.append(self.allocator, @unionInit(Instruction, "bipush", int));
            },
            .sipush => {
                const int_str = tok_iter.next() orelse return error.UnexpectedEnd;
                const int = try std.fmt.parseInt(i16, int_str, 10);
                try method.instructions.append(self.allocator, @unionInit(Instruction, "sipush", int));
            },
            inline .anewarray, .checkcast, .instanceof, .new, .newarray => |instr| {
                // .newarray technically takes a type and not a class, but both are strings in this case.
                // TODO: parse type passed to newarray
                const class_name = tok_iter.next() orelse return error.UnexpectedEnd;
                try method.instructions.append(self.allocator, @unionInit(Instruction, @tagName(instr), class_name));
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
            inline .invokespecial, .invokevirtual, .invokestatic => |instr| {
                const method_name = tok_iter.next() orelse return error.UnexpectedEnd;
                try method.instructions.append(self.allocator, @unionInit(Instruction, @tagName(instr), method_name));
            },
            inline //.ret,
            .aload, .astore, .dload, .dstore, .fload, .fstore, .iload, .istore, .lload, .lstore => |instr| {
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
        \\    invokespecial java/lang/Object/<init>()V
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
    try std.testing.expectEqual(@as(InstructionType, .invokespecial), init_method.instructions.items[1]);
    try std.testing.expectEqual(@as(InstructionType, .@"return"), init_method.instructions.items[2]);

    const main_method = parser.methods.items[1];
    try std.testing.expectEqual(@as(?u16, 2), main_method.stack_limit);
    try std.testing.expectEqual(@as(InstructionType, .getstatic), main_method.instructions.items[0]);
    try std.testing.expectEqual(@as(InstructionType, .ldc), main_method.instructions.items[1]);
    try std.testing.expectEqual(@as(InstructionType, .invokevirtual), main_method.instructions.items[2]);
    try std.testing.expectEqual(@as(InstructionType, .@"return"), main_method.instructions.items[3]);

    parser.setSource("HelloWorld.j");
    var class = try parser.toClassFile(std.testing.allocator);
    defer class.deinit();
}
