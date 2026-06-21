package org.dencliv.crypto.block.algorithm;

public interface AlgorithmFunction {
    int blockSize();

    void encryptBlock(byte[] input, int inputOffset, byte[] output, int outputOffset);

    void decryptBlock(byte[] input, int inputOffset, byte[] output, int outputOffset);
}
