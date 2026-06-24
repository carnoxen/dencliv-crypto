package org.dencliv.crypto.block.padding;

public interface Padding {
    byte[] add(byte[] input, int blockSize);

    byte[] remove(byte[] input, int blockSize);

    static Padding create(Class<? extends Padding> type) {
        try {
            return type.getConstructor().newInstance();
        } catch (ReflectiveOperationException exception) {
            throw new IllegalArgumentException("Unable to create padding: " + type.getName(), exception);
        }
    }
}
