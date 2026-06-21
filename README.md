# dencliv-crypto

A Java block-cipher library with combinable encryption and decryption APIs 
that don't need to declare checked exceptions.

```java
byte[] ciphertext = cipher.encrypt(key, iv, plaintext);
byte[] plaintext = cipher.decrypt(key, iv, ciphertext);
```

Invalid keys, IVs, padding, inputs, or authentication tags are reported with
runtime exceptions, so callers do not need `throws` declarations or checked
exception wrappers around normal crypto operations.

## Usage

Create a cipher by choosing an algorithm, operation mode, and padding:

```java
import org.dencliv.crypto.Library;

import static org.dencliv.crypto.block.algorithm.Algorithm.AES;
import static org.dencliv.crypto.block.operation.Operation.GCM;
import static org.dencliv.crypto.block.padding.Padding.No;

var cipher = Library.getBlockCipher(AES, GCM, No);

byte[] key = new byte[16];
byte[] nonce = new byte[12];
byte[] plaintext = "Hello, world!".getBytes(java.nio.charset.StandardCharsets.UTF_8);

byte[] ciphertext = cipher.encrypt(key, nonce, plaintext);
byte[] decrypted = cipher.decrypt(key, nonce, ciphertext);
```

For CBC with PKCS5 padding:

```java
import static org.dencliv.crypto.block.operation.Operation.CBC;
import static org.dencliv.crypto.block.padding.Padding.PKCS5;

var cipher = Library.getBlockCipher(AES, CBC, PKCS5);

byte[] key = java.util.HexFormat.of().parseHex(
        "000102030405060708090a0b0c0d0e0f");
byte[] iv = java.util.HexFormat.of().parseHex(
        "101112131415161718191a1b1c1d1e1f");
byte[] plaintext = "Hello, world!".getBytes(java.nio.charset.StandardCharsets.UTF_8);

byte[] ciphertext = cipher.encrypt(key, iv, plaintext);
byte[] decrypted = cipher.decrypt(key, iv, ciphertext);
```

Use a fresh, unpredictable IV or nonce for each encryption with the same key.
Never use an all-zero key or nonce in production; they are used above only to
keep the example short.

## Supported algorithms

### Block ciphers

| Algorithm | Key sizes |
| --- | --- |
| AES | 128, 192, or 256 bits |
| ARIA | 128, 192, or 256 bits |
| SEED | 128 bits |

### Operation modes

| Mode | Notes |
| --- | --- |
| CBC | Requires a 16-byte IV and complete padded blocks |
| CTR | Requires a 16-byte initial counter |
| OFB | Requires a 16-byte IV |
| CCM | Authenticated encryption; requires a 7-to-13-byte nonce |
| GCM | Authenticated encryption; a 12-byte nonce is recommended |

CCM and GCM append a 16-byte authentication tag to the ciphertext and verify it
during decryption.

### Padding

| Padding | Recommended use |
| --- | --- |
| `No` | CCM, CTR, GCM, OFB, or already block-aligned CBC input |
| `PKCS5` | CBC input of any length |
| `ISO10126` | CBC compatibility with systems that require ISO 10126 padding |

## Build and test

The project uses Java 25 and the Gradle wrapper:

```shell
./gradlew test
```

On Windows:

```powershell
.\gradlew.bat test
```
