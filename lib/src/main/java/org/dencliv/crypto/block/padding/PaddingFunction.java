package org.dencliv.crypto.block.padding;

interface PaddingFunction {
    byte[] add(byte[] input, int blockSize);

    byte[] remove(byte[] input, int blockSize);
}
