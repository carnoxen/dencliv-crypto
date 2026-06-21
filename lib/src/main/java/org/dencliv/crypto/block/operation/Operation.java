package org.dencliv.crypto.block.operation;

import org.dencliv.crypto.block.algorithm.AlgorithmFunction;

public enum Operation {
    CBC(new CBCFunction()),
    CCM(new CCMFunction()),
    CTR(new CTRFunction()),
    GCM(new GCMFunction()),
    OFB(new OFBFunction());

    private final OperationFunction function;

    Operation(OperationFunction function) {
        this.function = function;
    }

    public byte[] encrypt(AlgorithmFunction algorithm, byte[] iv, byte[] input) {
        return function.encrypt(algorithm, iv, input);
    }

    public byte[] decrypt(AlgorithmFunction algorithm, byte[] iv, byte[] input) {
        return function.decrypt(algorithm, iv, input);
    }
}
