.bytecode 55.0
.class public super NativeInvocationHandler
.super java/lang/Object
.implements java/lang/reflect/InvocationHandler

.field private ptr J

.method public <init>(J)V
    .limit stack 3
    .limit locals 3
    aload_0
    invokespecial java/lang/Object/<init>()V
    aload_0
    lload_1
    putfield NativeInvocationHandler/ptr J
    return
.end method

.method public invoke(Ljava/lang/Object;Ljava/lang/reflect/Method;[Ljava/lang/Object;)Ljava/lang/Object;
    .limit stack 4
    .limit locals 4
    aload_0
    aload_1
    aload_2
    aload_3
    invokevirtual NativeInvocationHandler/invoke0(Ljava/lang/Object;Ljava/lang/reflect/Method;[Ljava/lang/Object;)Ljava/lang/Object;
    areturn
.end method

.method native private invoke0(Ljava/lang/Object;Ljava/lang/reflect/Method;[Ljava/lang/Object;)Ljava/lang/Object;
.end method
