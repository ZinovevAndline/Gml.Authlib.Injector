/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package moe.yushi.authlibinjector.test;

import static org.junit.jupiter.api.Assertions.*;
import static org.objectweb.asm.Opcodes.*;

import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.function.Consumer;

import moe.yushi.authlibinjector.andline.AndlineEncryptedHandshakeTransformUnit;
import moe.yushi.authlibinjector.transform.TransformContext;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;

public class AndlineEncryptedHandshakeTransformUnitTest {
    private static final String HANDLER = "net.md_5.bungee.connection.InitialHandler";
    private static final String METHOD = "(Lnet/md_5/bungee/protocol/packet/EncryptionResponse;)V";

    private static byte[] buildFakeHandler() {
        ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        writer.visit(V1_8, ACC_PUBLIC, HANDLER.replace('.', '/'), null, "java/lang/Object", null);
        MethodVisitor mv = writer.visitMethod(ACC_PUBLIC, "handle", METHOD, null, null);
        mv.visitCode();
        mv.visitTypeInsn(NEW, "java/math/BigInteger");
        mv.visitInsn(DUP);
        mv.visitInsn(ICONST_1);
        mv.visitMethodInsn(INVOKESTATIC, "java/math/BigInteger", "valueOf", "(J)Ljava/math/BigInteger;", false);
        // Deliberate minimal bytecode: discard malformed temporary stack and
        // supply an actual BigInteger receiver using valueOf(1L).
        mv.visitInsn(POP);
        mv.visitInsn(POP);
        mv.visitInsn(LCONST_1);
        mv.visitMethodInsn(INVOKESTATIC, "java/math/BigInteger", "valueOf", "(J)Ljava/math/BigInteger;", false);
        mv.visitIntInsn(BIPUSH, 16);
        mv.visitMethodInsn(INVOKEVIRTUAL, "java/math/BigInteger", "toString", "(I)Ljava/lang/String;", false);
        mv.visitInsn(POP);
        mv.visitInsn(RETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();
        writer.visitEnd();
        return writer.toByteArray();
    }

    @Test
    public void insertsCallbackAfterTheRealHashStringAndPreservesOriginalCall() {
        byte[] source = buildFakeHandler();
        ClassReader reader = new ClassReader(source);
        ClassWriter output = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        final int[] callback = {0};
        final int[] modified = {0};

        TransformContext context = new TransformContext() {
            @Override public String getClassName() { return HANDLER; }
            @Override public boolean isInterface() { return false; }
            @Override public void markModified() { modified[0]++; }
            @Override public List<String> getStringConstants() { return Collections.emptyList(); }
            @Override public void invokeCallback(MethodVisitor mv, Class<?> owner, String name) {
                callback[0]++;
                assertEquals("registerEncryptedHash", name);
                mv.visitMethodInsn(INVOKESTATIC,
                        "moe/yushi/authlibinjector/andline/AndlineProviderSessions",
                        "registerEncryptedHash", "(Ljava/lang/Object;Ljava/lang/String;)V", false);
            }
            @Override public void addGeneratedMethod(String name, Consumer<ClassVisitor> generator) {}
        };

        Optional<ClassVisitor> transformed = new AndlineEncryptedHandshakeTransformUnit()
                .transform(null, HANDLER, output, context);
        assertTrue(transformed.isPresent());
        reader.accept(transformed.get(), 0);
        byte[] bytes = output.toByteArray();
        assertTrue(bytes.length > source.length);
        assertEquals(1, callback[0]);
        assertEquals(1, modified[0]);

        final int[] actual = {0};
        new ClassReader(bytes).accept(new ClassVisitor(ASM9) {
            @Override public MethodVisitor visitMethod(int access, String name, String desc,
                    String signature, String[] exceptions) {
                MethodVisitor downstream = super.visitMethod(access, name, desc, signature, exceptions);
                return new MethodVisitor(ASM9, downstream) {
                    @Override public void visitMethodInsn(int op, String owner, String method,
                            String descriptor, boolean itf) {
                        if (owner.equals("moe/yushi/authlibinjector/andline/AndlineProviderSessions")
                                && method.equals("registerEncryptedHash")) actual[0]++;
                    }
                };
            }
        }, 0);
        assertEquals(1, actual[0]);
    }

    @Test
    public void neverTransformsOtherClasses() {
        assertFalse(new AndlineEncryptedHandshakeTransformUnit().transform(
                null, "com.example.NotBungee", new ClassWriter(0), null).isPresent());
    }
}
