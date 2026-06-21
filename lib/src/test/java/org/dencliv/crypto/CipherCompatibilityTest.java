package org.dencliv.crypto;

import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.dencliv.crypto.block.BlockCipher;
import org.dencliv.crypto.block.operation.Operation;
import org.dencliv.crypto.block.padding.Padding;
import org.junit.jupiter.api.Test;

import static org.dencliv.crypto.block.algorithm.Algorithm.AES;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

class CipherCompatibilityTest {
    private static final byte[] KEY = hex("000102030405060708090a0b0c0d0e0f");
    private static final byte[] IV = hex("101112131415161718191a1b1c1d1e1f");
    private static final byte[] NONCE = hex("101112131415161718191a1b");
    private static final byte[] COMPLETE_BLOCKS = hex(
            "00112233445566778899aabbccddeeff"
                    + "102132435465768798a9bacbdcedfe0f");
    private static final byte[] PARTIAL_BLOCK = hex(
            "00112233445566778899aabbccddeeff1021324354");

    @Test
    void matchesJavaCipherForDeterministicTransformations() throws Exception {
        compare(Operation.CBC, Padding.No, COMPLETE_BLOCKS, IV);
        compare(Operation.CBC, Padding.PKCS5, PARTIAL_BLOCK, IV);
        compare(Operation.CTR, Padding.No, PARTIAL_BLOCK, IV);
        compare(Operation.OFB, Padding.No, PARTIAL_BLOCK, IV);
        compare(Operation.OFB, Padding.PKCS5, PARTIAL_BLOCK, IV);
        compare(Operation.GCM, Padding.No, PARTIAL_BLOCK, NONCE);
    }

    @Test
    void interoperatesWithJavaCipherForIso10126Padding() throws Exception {
        interoperate(Operation.CBC, Padding.ISO10126, PARTIAL_BLOCK, IV);
        interoperate(Operation.OFB, Padding.ISO10126, PARTIAL_BLOCK, IV);
    }

    private static void compare(
            Operation operation,
            Padding padding,
            byte[] plaintext,
            byte[] iv) throws Exception {
        var library = Library.getBlockCipher(AES, operation, padding);
        var javaCiphertext = crypt(library, Cipher.ENCRYPT_MODE, iv, plaintext);
        var libraryCiphertext = library.encrypt(KEY, iv, plaintext);

        assertEquals(transformation(operation, padding), library.getFallback().getAlgorithm());
        assertArrayEquals(javaCiphertext, libraryCiphertext);
        assertArrayEquals(plaintext, library.decrypt(KEY, iv, javaCiphertext));
        assertArrayEquals(plaintext, crypt(library, Cipher.DECRYPT_MODE, iv, libraryCiphertext));
    }

    private static void interoperate(
            Operation operation,
            Padding padding,
            byte[] plaintext,
            byte[] iv) throws Exception {
        var library = Library.getBlockCipher(AES, operation, padding);
        var libraryCiphertext = library.encrypt(KEY, iv, plaintext);
        var javaCiphertext = crypt(library, Cipher.ENCRYPT_MODE, iv, plaintext);

        assertEquals(transformation(operation, padding), library.getFallback().getAlgorithm());
        assertArrayEquals(plaintext, crypt(library, Cipher.DECRYPT_MODE, iv, libraryCiphertext));
        assertArrayEquals(plaintext, library.decrypt(KEY, iv, javaCiphertext));
    }

    private static byte[] crypt(
            BlockCipher library,
            int mode,
            byte[] iv,
            byte[] input) throws Exception {
        var cipher = library.getFallback();
        var key = new SecretKeySpec(KEY, AES.name());
        AlgorithmParameterSpec parameters = library.operation() == Operation.GCM
                ? new GCMParameterSpec(128, iv)
                : new IvParameterSpec(iv);
        cipher.init(mode, key, parameters);
        return cipher.doFinal(input);
    }

    private static String transformation(Operation operation, Padding padding) {
        return "AES/%s/%sPadding".formatted(operation, padding);
    }

    private static byte[] hex(String value) {
        return java.util.HexFormat.of().parseHex(value);
    }
}
