package org.dencliv.crypto;

import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.Test;

import static org.dencliv.crypto.block.algorithm.Algorithm.AES;
import static org.dencliv.crypto.block.algorithm.Algorithm.ARIA;
import static org.dencliv.crypto.block.algorithm.Algorithm.SEED;
import static org.dencliv.crypto.block.operation.Operation.CBC;
import static org.dencliv.crypto.block.operation.Operation.CCM;
import static org.dencliv.crypto.block.operation.Operation.CTR;
import static org.dencliv.crypto.block.operation.Operation.GCM;
import static org.dencliv.crypto.block.operation.Operation.OFB;
import static org.dencliv.crypto.block.padding.Padding.ISO10126;
import static org.dencliv.crypto.block.padding.Padding.No;
import static org.dencliv.crypto.block.padding.Padding.PKCS5;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class OperationTest {
    @Test
    void encryptsAndDecryptsAriaBlocks() {
        var plaintext = hex("00112233445566778899aabbccddeeff");
        var keys = new String[]{
                "000102030405060708090a0b0c0d0e0f",
                "000102030405060708090a0b0c0d0e0f1011121314151617",
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        };
        var ciphertexts = new String[]{
                "d718fbd6ab644c739da95f3be6451778",
                "26449c1805dbe7aa25a468ce263a9e79",
                "f92bd7c79fb72e2f2b8f80c1972d24fc"
        };

        for (var index = 0; index < keys.length; index++) {
            var algorithm = ARIA.create(hex(keys[index]));
            var ciphertext = new byte[16];
            var decrypted = new byte[16];

            algorithm.encryptBlock(plaintext, 0, ciphertext, 0);
            algorithm.decryptBlock(ciphertext, 0, decrypted, 0);

            assertArrayEquals(hex(ciphertexts[index]), ciphertext);
            assertArrayEquals(plaintext, decrypted);
        }
    }

    @Test
    void rejectsInvalidAriaKeySize() {
        var exception = assertThrows(IllegalArgumentException.class, () -> ARIA.create(new byte[20]));

        assertEquals("ARIA key must be 16, 24, or 32 bytes", exception.getMessage());
    }

    @Test
    void encryptsAndDecryptsSeedBlock() {
        var algorithm = SEED.create(hex("00000000000000000000000000000000"));
        var plaintext = hex("000102030405060708090a0b0c0d0e0f");
        var ciphertext = new byte[16];
        var decrypted = new byte[16];

        algorithm.encryptBlock(plaintext, 0, ciphertext, 0);
        algorithm.decryptBlock(ciphertext, 0, decrypted, 0);

        assertArrayEquals(hex("5ebac6e0054e166819aff1cc6d346cdb"), ciphertext);
        assertArrayEquals(plaintext, decrypted);
    }

    @Test
    void encryptsAndDecryptsSeedCbc() {
        var cipher = Library.getBlockCipher(SEED, CBC, PKCS5);
        var key = hex("000102030405060708090a0b0c0d0e0f");
        var iv = hex("101112131415161718191a1b1c1d1e1f");
        var plaintext = hex("00112233445566778899aabbccddeeff");

        var ciphertext = cipher.encrypt(key, iv, plaintext);

        assertArrayEquals(plaintext, cipher.decrypt(key, iv, ciphertext));
    }

    @Test
    void encryptsAndDecryptsAesCbc() {
        var cipher = Library.getBlockCipher(AES, CBC, PKCS5);
        var key = hex("2b7e151628aed2a6abf7158809cf4f3c");
        var iv = hex("000102030405060708090a0b0c0d0e0f");
        var plaintext = hex("6bc1bee22e409f96e93d7e117393172a");

        var ciphertext = cipher.encrypt(key, iv, plaintext);

        assertArrayEquals(hex("7649abac8119b246cee98e9b12e9197d"),
                java.util.Arrays.copyOf(ciphertext, 16));
        assertArrayEquals(plaintext, cipher.decrypt(key, iv, ciphertext));
    }

    @Test
    void encryptsAndDecryptsAesCtr() {
        var cipher = Library.getBlockCipher(AES, CTR, No);
        var key = hex("2b7e151628aed2a6abf7158809cf4f3c");
        var counter = hex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        var plaintext = hex("6bc1bee22e409f96e93d7e117393172aae2d8a57");

        var ciphertext = cipher.encrypt(key, counter, plaintext);

        assertArrayEquals(hex("874d6191b620e3261bef6864990db6ce9806f66b"), ciphertext);
        assertArrayEquals(plaintext, cipher.decrypt(key, counter, ciphertext));
    }

    @Test
    void encryptsAesCtrLikeJavaNoPadding() throws Exception {
        var cipher = Library.getBlockCipher(AES, CTR, No);
        var key = hex("2b7e151628aed2a6abf7158809cf4f3c");
        var counter = hex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        var plaintext = hex("6bc1bee22e409f96e93d7e117393172aae2d8a57");
        var fallback = cipher.getFallback();

        fallback.init(
                Cipher.ENCRYPT_MODE,
                new SecretKeySpec(key, AES.name()),
                new IvParameterSpec(counter));

        assertEquals("AES/CTR/NoPadding", fallback.getAlgorithm());
        assertArrayEquals(fallback.doFinal(plaintext), cipher.encrypt(key, counter, plaintext));
    }

    @Test
    void encryptsAndDecryptsAesOfb() {
        var algorithm = AES.create(hex("2b7e151628aed2a6abf7158809cf4f3c"));
        var iv = hex("000102030405060708090a0b0c0d0e0f");
        var plaintext = hex("6bc1bee22e409f96e93d7e117393172a");

        var ciphertext = OFB.encrypt(algorithm, iv, plaintext);

        assertArrayEquals(hex("3b3fd92eb72dad20333449f8e83cfb4a"), ciphertext);
        assertArrayEquals(plaintext, OFB.decrypt(algorithm, iv, ciphertext));
    }

    @Test
    void encryptsAndDecryptsAesGcm() {
        var algorithm = AES.create(new byte[16]);
        var iv = new byte[12];
        var plaintext = new byte[16];

        var ciphertext = GCM.encrypt(algorithm, iv, plaintext);

        assertArrayEquals(hex(
                "0388dace60b6a392f328c2b971b2fe78"
                        + "ab6e47d42cec13bdf53a67b21257bddf"), ciphertext);
        assertArrayEquals(plaintext, GCM.decrypt(algorithm, iv, ciphertext));
    }

    @Test
    void encryptsAndDecryptsAesCcm() {
        var algorithm = AES.create(hex("404142434445464748494a4b4c4d4e4f"));
        var nonce = hex("10111213141516");
        var plaintext = hex("20212223");

        var ciphertext = CCM.encrypt(algorithm, nonce, plaintext);

        assertArrayEquals(hex("7162015b"), java.util.Arrays.copyOf(ciphertext, 4));
        assertArrayEquals(plaintext, CCM.decrypt(algorithm, nonce, ciphertext));
    }

    @Test
    void rejectsModifiedAuthenticationTags() {
        var algorithm = AES.create(new byte[16]);
        var ciphertext = GCM.encrypt(algorithm, new byte[12], new byte[16]);
        ciphertext[ciphertext.length - 1] ^= 1;

        var exception = assertThrows(
                IllegalArgumentException.class,
                () -> GCM.decrypt(algorithm, new byte[12], ciphertext));

        assertEquals("Invalid authentication tag", exception.getMessage());
    }

    @Test
    void createsCompatibleFallbackCipher() throws Exception {
        var cipher = Library.getBlockCipher(AES, CBC, PKCS5);
        var key = hex("2b7e151628aed2a6abf7158809cf4f3c");
        var iv = hex("000102030405060708090a0b0c0d0e0f");
        var plaintext = hex("6bc1bee22e409f96e93d7e117393172a");
        var fallback = cipher.getFallback();

        fallback.init(
                Cipher.ENCRYPT_MODE,
                new SecretKeySpec(key, AES.name()),
                new IvParameterSpec(iv));

        assertEquals("AES/CBC/PKCS5Padding", fallback.getAlgorithm());
        assertArrayEquals(cipher.encrypt(key, iv, plaintext), fallback.doFinal(plaintext));
    }

    @Test
    void interoperatesWithJavaIso10126Padding() throws Exception {
        var cipher = Library.getBlockCipher(AES, CBC, ISO10126);
        var key = hex("2b7e151628aed2a6abf7158809cf4f3c");
        var iv = hex("000102030405060708090a0b0c0d0e0f");
        var plaintext = hex("6bc1bee22e409f96e93d7e117393172aae2d8a57");
        var fallback = cipher.getFallback();
        var secretKey = new SecretKeySpec(key, AES.name());
        var parameters = new IvParameterSpec(iv);

        fallback.init(Cipher.DECRYPT_MODE, secretKey, parameters);
        assertEquals("AES/CBC/ISO10126Padding", fallback.getAlgorithm());
        assertArrayEquals(plaintext, fallback.doFinal(cipher.encrypt(key, iv, plaintext)));

        fallback.init(Cipher.ENCRYPT_MODE, secretKey, parameters);
        assertArrayEquals(plaintext, cipher.decrypt(key, iv, fallback.doFinal(plaintext)));
    }

    @Test
    void rejectsUnsupportedFallbackTransformation() {
        var cipher = Library.getBlockCipher(AES, CTR, PKCS5);

        var exception = assertThrows(NoSuchAlgorithmException.class, cipher::getFallback);

        assertEquals(NoSuchPaddingException.class, exception.getCause().getClass());
    }

    private static byte[] hex(String value) {
        return java.util.HexFormat.of().parseHex(value);
    }
}
