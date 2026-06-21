package org.dencliv.crypto.block.padding;

public enum Padding {
    PKCS5(new PKCS5Function());

    private final PaddingFunction function;

    Padding(PaddingFunction function) {
        this.function = function;
    }

    public byte[] add(byte[] input, int blockSize) {
        return function.add(input, blockSize);
    }

    public byte[] remove(byte[] input, int blockSize) {
        return function.remove(input, blockSize);
    }

    public String transformationName() {
        return name() + "Padding";
    }
}
