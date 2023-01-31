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
