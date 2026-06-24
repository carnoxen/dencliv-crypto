package org.dencliv.crypto;

import org.dencliv.crypto.block.BlockCipher;
import org.dencliv.crypto.block.algorithm.Algorithm;
import org.dencliv.crypto.block.operation.Operation;
import org.dencliv.crypto.block.padding.Padding;

import java.util.Objects;

public final class Library {
    private Library() {
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
