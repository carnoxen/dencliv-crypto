package org.dencliv.crypto.block.padding;

final class NoFunction implements PaddingFunction {
    @Override
    public byte[] add(byte[] input, int blockSize) {
        return input.clone();
    }

    @Override
    public byte[] remove(byte[] input, int blockSize) {
        return input.clone();
    }
}
