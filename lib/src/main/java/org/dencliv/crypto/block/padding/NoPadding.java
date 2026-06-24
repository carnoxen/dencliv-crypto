package org.dencliv.crypto.block.padding;

public final class NoPadding implements Padding {
    @Override
    public byte[] add(byte[] input, int blockSize) {
        return input.clone();
    }

    @Override
    public byte[] remove(byte[] input, int blockSize) {
        return input.clone();
    }
}
