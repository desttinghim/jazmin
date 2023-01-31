# Jazmin - JVM Assembler in Zig

Jazmin is a reimplemention of [jasmin][jasmin] in zig.
Jasmin is an assembly language for the Java Virtual Machine.

## Dependencies

- `zig` nightly (last tested on `0.11.0-dev.1302+d813cef42`)
- `java` (tested on openjdk "17.0.4")

## Getting started

``` sh
git clone --recursive https://github.com/desttinghim/jazmin
cd jazmin
zig build run -- examples/HelloWorld.j HelloWorld.class
java HelloWorld
```

## Example

Check out the `examples/` subfolder. This is hello world in jasmin:

``` jasmin
.class public HelloWorld
.super java/lang/Object

; standard initializer (calls java.lang.Object's initializer)
.method public <init>()V
    aload_0
    invokespecial java/lang/Object/<init>()V
    return
.end method

; main() - prints out Hello World
.method public static main([Ljava/lang/String;)V
    .limit stack 2  ; up to two items can be pushed
    getstatic java/lang/System/out Ljava/io/PrintStream;
    ldc "Hello, World!"
    invokevirtual java/io/PrintStream/println(Ljava/lang/String;)V
    return
.end method
```

[jasmin]: https://jasmin.sourceforge.net/
