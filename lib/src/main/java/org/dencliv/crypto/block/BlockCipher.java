package org.dencliv.crypto.block;

import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

import org.dencliv.crypto.block.algorithm.Algorithm;
import org.dencliv.crypto.block.operation.Operation;
import org.dencliv.crypto.block.padding.Padding;

public final class BlockCipher {
    private final Algorithm algorithm;
    private final Operation operation;
    private final Padding padding;

    public BlockCipher(Algorithm algorithm, Operation operation, Padding padding) {
        this.algorithm = algorithm;
        this.operation = operation;
        this.padding = padding;
    }

    public byte[] encrypt(byte[] key, byte[] iv, byte[] input) {
        var blockAlgorithm = algorithm.create(key);
        return operation.encrypt(
                blockAlgorithm,
                iv,
                padding.add(input, blockAlgorithm.blockSize()));
    }

    public byte[] decrypt(byte[] key, byte[] iv, byte[] input) {
        var blockAlgorithm = algorithm.create(key);
        return padding.remove(
                operation.decrypt(blockAlgorithm, iv, input),
                blockAlgorithm.blockSize());
    }

    public Algorithm algorithm() {
        return algorithm;
    }

    public Operation operation() {
        return operation;
    }

    public Padding padding() {
        return padding;
    }

    public Cipher getFallback() throws NoSuchAlgorithmException, NoSuchPaddingException {
        String algorithmName = algorithm.name();
        String operationName = operation.name();
        String paddingName = padding.name();
        
        return Cipher.getInstance("%s/%s/%sPadding".formatted(algorithmName, operationName, paddingName));
    }
}
