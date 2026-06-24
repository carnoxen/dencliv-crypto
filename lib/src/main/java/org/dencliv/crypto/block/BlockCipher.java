package org.dencliv.crypto.block;

import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

import org.dencliv.crypto.block.algorithm.Algorithm;
import org.dencliv.crypto.block.operation.Operation;
import org.dencliv.crypto.block.padding.Padding;

public final class BlockCipher {
    private final Class<? extends Algorithm> algorithm;
    private final Class<? extends Operation> operation;
    private final Class<? extends Padding> padding;

    public BlockCipher(
            Class<? extends Algorithm> algorithm,
            Class<? extends Operation> operation,
            Class<? extends Padding> padding) {
        this.algorithm = algorithm;
        this.operation = operation;
        this.padding = padding;
    }

    public byte[] encrypt(byte[] key, byte[] iv, byte[] input) {
        var blockAlgorithm = Algorithm.create(algorithm, key);
        var blockPadding = Padding.create(padding);
        return Operation.create(operation).encrypt(
                blockAlgorithm,
                iv,
                blockPadding.add(input, blockAlgorithm.blockSize()));
    }

    public byte[] decrypt(byte[] key, byte[] iv, byte[] input) {
        var blockAlgorithm = Algorithm.create(algorithm, key);
        var blockPadding = Padding.create(padding);
        return blockPadding.remove(
                Operation.create(operation).decrypt(blockAlgorithm, iv, input),
                blockAlgorithm.blockSize());
    }

    public Class<? extends Algorithm> algorithm() {
        return algorithm;
    }

    public Class<? extends Operation> operation() {
        return operation;
    }

    public Class<? extends Padding> padding() {
        return padding;
    }

    public Cipher getFallback() throws NoSuchAlgorithmException, NoSuchPaddingException {
        return Cipher.getInstance("%s/%s/%s".formatted(
                algorithm.getSimpleName(),
                operation.getSimpleName(),
                padding.getSimpleName()));
    }
}
