/*
 * ANDLINE extensions to authlib-injector.
 * Copyright (C) 2026 ANDLINE contributors.
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package moe.yushi.authlibinjector.andline;

import static org.objectweb.asm.Opcodes.ALOAD;
import static org.objectweb.asm.Opcodes.ASM9;
import static org.objectweb.asm.Opcodes.DUP;
import static org.objectweb.asm.Opcodes.INVOKEVIRTUAL;
import static org.objectweb.asm.Opcodes.SWAP;

import java.util.Optional;
import moe.yushi.authlibinjector.transform.TransformContext;
import moe.yushi.authlibinjector.transform.TransformUnit;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;

/**
 * Capture the real session hash in Bungee InitialHandler, after the encrypted
 * handshake is proven and before the authoritative hasJoined HTTP request.
 *
 * This is opt-in and version-specific. Unsupported proxy bytecode must fail
 * closed, never route using a pre-login nickname or virtual host alone.
 */
public final class AndlineEncryptedHandshakeTransformUnit implements TransformUnit {
    @Override
    public Optional<ClassVisitor> transform(ClassLoader loader, String className,
            ClassVisitor writer, TransformContext context) {
        if (!"net.md_5.bungee.connection.InitialHandler".equals(className)) {
            return Optional.empty();
        }

        return Optional.of(new ClassVisitor(ASM9, writer) {
            @Override
            public MethodVisitor visitMethod(int access, String name, String descriptor,
                    String signature, String[] exceptions) {
                MethodVisitor delegate = super.visitMethod(access, name, descriptor,
                        signature, exceptions);
                if (!"handle".equals(name)
                        || !"(Lnet/md_5/bungee/protocol/packet/EncryptionResponse;)V".equals(descriptor)) {
                    return delegate;
                }

                return new MethodVisitor(ASM9, delegate) {
                    @Override
                    public void visitMethodInsn(int opcode, String owner, String method,
                            String desc, boolean isInterface) {
                        super.visitMethodInsn(opcode, owner, method, desc, isInterface);
                        if (opcode == INVOKEVIRTUAL && !isInterface
                                && "java/math/BigInteger".equals(owner)
                                && "toString".equals(method)
                                && "(I)Ljava/lang/String;".equals(desc)) {
                            // Stack before: [serverHash]. Preserve it for the
                            // original URLEncoder.encode() call.
                            super.visitInsn(DUP);       // [hash, hash]
                            super.visitVarInsn(ALOAD, 0); // [hash, hash, InitialHandler]
                            super.visitInsn(SWAP);      // [hash, InitialHandler, hash]
                            context.invokeCallback(this, AndlineProviderSessions.class,
                                    "registerEncryptedHash");
                            context.markModified();
                        }
                    }
                };
            }
        });
    }

    @Override
    public String toString() {
        return "ANDLINE Bungee encrypted-session provider route";
    }
}
