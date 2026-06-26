package org.dencliv.crypto.symmetric.operation;

import org.dencliv.crypto.symmetric.algorithm.Algorithm;

public interface Operation {
    byte[] encrypt(Algorithm algorithm, byte[] iv, byte[] input);

    byte[] decrypt(Algorithm algorithm, byte[] iv, byte[] input);

    static Operation create(Class<? extends Operation> type) {
        try {
            return type.getConstructor().newInstance();
        } catch (ReflectiveOperationException exception) {
            throw new IllegalArgumentException("Unable to create operation: " + type.getName(), exception);
        }
    }
}
