package org.dencliv.crypto;

import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.dencliv.crypto.block.BlockCipher;
import org.dencliv.crypto.block.algorithm.AES;
import org.dencliv.crypto.block.algorithm.Blowfish;
import org.dencliv.crypto.block.operation.CBC;
import org.dencliv.crypto.block.operation.CTR;
import org.dencliv.crypto.block.operation.GCM;
import org.dencliv.crypto.block.operation.OFB;
import org.dencliv.crypto.block.operation.Operation;
import org.dencliv.crypto.block.padding.ISO10126Padding;
import org.dencliv.crypto.block.padding.NoPadding;
import org.dencliv.crypto.block.padding.Padding;
import org.dencliv.crypto.block.padding.PKCS5Padding;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class FallbackTest {
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
        compare(CBC.class, NoPadding.class, COMPLETE_BLOCKS, IV);
        compare(CBC.class, PKCS5Padding.class, PARTIAL_BLOCK, IV);
        compare(CTR.class, NoPadding.class, PARTIAL_BLOCK, IV);
        compare(OFB.class, NoPadding.class, PARTIAL_BLOCK, IV);
        compare(OFB.class, PKCS5Padding.class, PARTIAL_BLOCK, IV);
        compare(GCM.class, NoPadding.class, PARTIAL_BLOCK, NONCE);
    }

    @Test
    void interoperatesWithJavaCipherForIso10126Padding() throws Exception {
        interoperate(CBC.class, ISO10126Padding.class, PARTIAL_BLOCK, IV);
        interoperate(OFB.class, ISO10126Padding.class, PARTIAL_BLOCK, IV);
    }

    @Test
    void encryptsBlowfishCbcLikeJava() throws Exception {
        var library = Library.getBlockCipher(Blowfish.class, CBC.class, PKCS5Padding.class);
        var key = hex("0123456789abcdeff0e1d2c3b4a59687");
        var iv = hex("fedcba9876543210");
        var plaintext = hex("37363534333231204e6f77206973207468652074696d6520666f7220");
        var fallback = library.getFallback();

        fallback.init(
                Cipher.ENCRYPT_MODE,
                new SecretKeySpec(key, Blowfish.class.getSimpleName()),
                new IvParameterSpec(iv));

        assertEquals("Blowfish", Blowfish.class.getSimpleName());
        assertEquals("Blowfish/CBC/PKCS5Padding", fallback.getAlgorithm());
        assertArrayEquals(fallback.doFinal(plaintext), library.encrypt(key, iv, plaintext));
        assertArrayEquals(plaintext, library.decrypt(key, iv, library.encrypt(key, iv, plaintext)));
    }

    @Test
    void encryptsAesCtrLikeJavaNoPadding() throws Exception {
        var library = Library.getBlockCipher(AES.class, CTR.class, NoPadding.class);
        var key = hex("2b7e151628aed2a6abf7158809cf4f3c");
        var counter = hex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        var plaintext = hex("6bc1bee22e409f96e93d7e117393172aae2d8a57");
        var fallback = library.getFallback();

        fallback.init(
                Cipher.ENCRYPT_MODE,
                new SecretKeySpec(key, AES.class.getSimpleName()),
                new IvParameterSpec(counter));

        assertEquals("AES/CTR/NoPadding", fallback.getAlgorithm());
        assertArrayEquals(fallback.doFinal(plaintext), library.encrypt(key, counter, plaintext));
    }

    @Test
    void createsCompatibleFallbackCipher() throws Exception {
        var library = Library.getBlockCipher(AES.class, CBC.class, PKCS5Padding.class);
        var key = hex("2b7e151628aed2a6abf7158809cf4f3c");
        var iv = hex("000102030405060708090a0b0c0d0e0f");
        var plaintext = hex("6bc1bee22e409f96e93d7e117393172a");
        var fallback = library.getFallback();

        fallback.init(
                Cipher.ENCRYPT_MODE,
                new SecretKeySpec(key, AES.class.getSimpleName()),
                new IvParameterSpec(iv));

        assertEquals("AES/CBC/PKCS5Padding", fallback.getAlgorithm());
        assertArrayEquals(library.encrypt(key, iv, plaintext), fallback.doFinal(plaintext));
    }

    @Test
    void interoperatesWithJavaIso10126Padding() throws Exception {
        var library = Library.getBlockCipher(AES.class, CBC.class, ISO10126Padding.class);
        var key = hex("2b7e151628aed2a6abf7158809cf4f3c");
        var iv = hex("000102030405060708090a0b0c0d0e0f");
        var plaintext = hex("6bc1bee22e409f96e93d7e117393172aae2d8a57");
        var fallback = library.getFallback();
        var secretKey = new SecretKeySpec(key, AES.class.getSimpleName());
        var parameters = new IvParameterSpec(iv);

        fallback.init(Cipher.DECRYPT_MODE, secretKey, parameters);
        assertEquals("AES/CBC/ISO10126Padding", fallback.getAlgorithm());
        assertArrayEquals(plaintext, fallback.doFinal(library.encrypt(key, iv, plaintext)));

        fallback.init(Cipher.ENCRYPT_MODE, secretKey, parameters);
        assertArrayEquals(plaintext, library.decrypt(key, iv, fallback.doFinal(plaintext)));
    }

    @Test
    void rejectsUnsupportedFallbackTransformation() {
        var library = Library.getBlockCipher(AES.class, CTR.class, PKCS5Padding.class);

        var exception = assertThrows(NoSuchAlgorithmException.class, library::getFallback);

        assertEquals(NoSuchPaddingException.class, exception.getCause().getClass());
    }

    private static void compare(
            Class<? extends Operation> operation,
            Class<? extends Padding> padding,
            byte[] plaintext,
            byte[] iv) throws Exception {
        var library = Library.getBlockCipher(AES.class, operation, padding);
        var javaCiphertext = crypt(library, Cipher.ENCRYPT_MODE, iv, plaintext);
        var libraryCiphertext = library.encrypt(KEY, iv, plaintext);

        assertEquals(transformation(operation, padding), library.getFallback().getAlgorithm());
        assertArrayEquals(javaCiphertext, libraryCiphertext);
        assertArrayEquals(plaintext, library.decrypt(KEY, iv, javaCiphertext));
        assertArrayEquals(plaintext, crypt(library, Cipher.DECRYPT_MODE, iv, libraryCiphertext));
    }

    private static void interoperate(
            Class<? extends Operation> operation,
            Class<? extends Padding> padding,
            byte[] plaintext,
            byte[] iv) throws Exception {
        var library = Library.getBlockCipher(AES.class, operation, padding);
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
        var key = new SecretKeySpec(KEY, AES.class.getSimpleName());
        AlgorithmParameterSpec parameters = library.operation() == GCM.class
                ? new GCMParameterSpec(128, iv)
                : new IvParameterSpec(iv);
        cipher.init(mode, key, parameters);
        return cipher.doFinal(input);
    }

    private static String transformation(Class<? extends Operation> operation, Class<? extends Padding> padding) {
        return "AES/%s/%s".formatted(operation.getSimpleName(), padding.getSimpleName());
    }

    private static byte[] hex(String value) {
        return java.util.HexFormat.of().parseHex(value);
    }
}
