package org.dencliv.crypto;

import java.util.Objects;

import org.dencliv.crypto.symmetric.BlockCipher;
import org.dencliv.crypto.symmetric.algorithm.Algorithm;
import org.dencliv.crypto.symmetric.operation.Operation;
import org.dencliv.crypto.symmetric.padding.Padding;

public final class Crypto {
    private Crypto() {
    }

    public static BlockCipher getBlockCipher(
            Class<? extends Algorithm> algorithm,
            Class<? extends Operation> operation,
            Class<? extends Padding> padding) {
        return new BlockCipher(
                Objects.requireNonNull(algorithm, "algorithm"),
                Objects.requireNonNull(operation, "operation"),
                Objects.requireNonNull(padding, "padding"));
    }
}
