package org.dencliv.crypto.block.operation;

import org.dencliv.crypto.block.algorithm.AlgorithmFunction;

interface OperationFunction {
    byte[] encrypt(AlgorithmFunction algorithm, byte[] iv, byte[] input);

    byte[] decrypt(AlgorithmFunction algorithm, byte[] iv, byte[] input);
}
