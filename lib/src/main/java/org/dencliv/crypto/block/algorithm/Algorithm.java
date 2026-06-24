package org.dencliv.crypto.block.algorithm;

import java.lang.reflect.InvocationTargetException;

public interface Algorithm {
    int blockSize();

    void encryptBlock(byte[] input, int inputOffset, byte[] output, int outputOffset);

    void decryptBlock(byte[] input, int inputOffset, byte[] output, int outputOffset);

    static Algorithm create(Class<? extends Algorithm> type, byte[] key) {
        try {
            return type.getConstructor(byte[].class).newInstance(key);
        } catch (InvocationTargetException exception) {
            if (exception.getCause() instanceof RuntimeException runtimeException) {
                throw runtimeException;
            }
            throw new IllegalArgumentException("Unable to create algorithm: " + type.getName(), exception.getCause());
        } catch (ReflectiveOperationException exception) {
            throw new IllegalArgumentException("Unable to create algorithm: " + type.getName(), exception);
        }
    }
}
