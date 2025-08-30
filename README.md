# IPCrypt Java Implementation

This is a Java implementation of the IPCrypt specification as defined in [draft-denis-ipcrypt](https://github.com/jedisct1/draft-denis-ipcrypt).

## Overview

IPCrypt provides methods for encrypting and obfuscating IP addresses for privacy-preserving storage, logging, and analytics. This implementation includes all three variants defined in the specification:

1. **ipcrypt-deterministic** - Deterministic, format-preserving encryption using AES-128
2. **ipcrypt-nd** - Non-deterministic encryption using KIASU-BC with an 8-byte tweak
3. **ipcrypt-ndx** - Non-deterministic encryption using AES-XTS with a 16-byte tweak

## Features

- **Readable and idiomatic Java code**
- **Correct implementation** matching the specification
- **All test vectors pass** as defined in the draft specification
- **No external dependencies** (uses only standard Java libraries)
- **Consolidated utility methods** to reduce code duplication

## Building

To build the project, you need Maven installed:

```bash
mvn compile
```

## Running Tests

To run the tests:

```bash
# Run basic tests
mvn exec:java -Dexec.mainClass="com.ipcrypt.IPCryptTest"

# Run comprehensive tests with all test vectors
mvn exec:java -Dexec.mainClass="com.ipcrypt.IPCryptComprehensiveTest"
```

## Usage

### Deterministic Encryption (ipcrypt-deterministic)

```java
// Encrypt an IP address
byte[] key = IPCryptUtils.hexToBytes("0123456789abcdeffedcba9876543210");
InetAddress encrypted = IPCryptDeterministic.encrypt("192.0.2.1", key);

// Decrypt an IP address
InetAddress decrypted = IPCryptDeterministic.decrypt(encrypted, key);
```

### Non-Deterministic Encryption with KIASU-BC (ipcrypt-nd)

```java
// Encrypt an IP address with a specific tweak
byte[] key = IPCryptUtils.hexToBytes("0123456789abcdeffedcba9876543210");
byte[] tweak = IPCryptUtils.hexToBytes("08e0c289bff23b7c");
byte[] encrypted = IPCryptND.encrypt("192.0.2.1", key, tweak);

// Encrypt an IP address with a random tweak
byte[] encryptedRandom = IPCryptND.encrypt("192.0.2.1", key, null);

// Decrypt an IP address
InetAddress decrypted = IPCryptND.decrypt(encrypted, key);
```

### Non-Deterministic Encryption with AES-XTS (ipcrypt-ndx)

```java
// Encrypt an IP address
byte[] key = IPCryptUtils.hexToBytes("0123456789abcdeffedcba98765432101032547698badcfeefcdab8967452301");
byte[] encrypted = IPCryptNDX.encrypt("192.0.2.1", key);

// Decrypt an IP address
InetAddress decrypted = IPCryptNDX.decrypt(encrypted, key);
```

## Implementation Details

### IPCryptUtils

A utility class that provides common functionality:
- IP address conversion between string and byte representations
- Hex string to byte array conversion and vice versa

### ipcrypt-deterministic

- Uses AES-128 in ECB mode (as specified)
- Key must be exactly 16 bytes
- Output is always the same for the same input and key

### ipcrypt-nd

- Uses KIASU-BC tweakable block cipher
- Key must be exactly 16 bytes
- Tweak must be exactly 8 bytes
- Output varies based on the tweak value

### ipcrypt-ndx

- Uses AES-XTS tweakable block cipher
- Key must be exactly 32 bytes (two AES-128 keys)
- Tweak is randomly generated as 16 bytes
- Output varies based on the randomly generated tweak

## Test Vectors

All test vectors from the specification have been implemented and verified:

- 5 ipcrypt-deterministic test vectors
- 5 ipcrypt-nd test vectors  
- 5 ipcrypt-ndx test vectors

The implementation passes all test vectors correctly.

## Security Notes

- Keys should be generated using a cryptographically secure random number generator
- For production use, ensure keys are stored securely
- The implementation follows the specification exactly as defined