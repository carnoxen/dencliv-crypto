package org.dencliv.crypto.block.algorithm;

import java.util.function.Function;

public enum Algorithm {
    AES(AESFunction::new),
    ARIA(ARIAFunction::new),
    SEED(SEEDFunction::new);

    private final Function<byte[], AlgorithmFunction> factory;

    Algorithm(Function<byte[], AlgorithmFunction> factory) {
        this.factory = factory;
    }

    public AlgorithmFunction create(byte[] key) {
        return factory.apply(key);
    }
}
