# SecurityUtils

SecurityUtils is a Java utility library that provides essential cryptographic functions, including hashing, password security, and encryption/decryption mechanisms. It is designed to simplify security-related operations in Java applications.

## Features
- **Hashing Algorithms**: SHA-256 and SHA-512 with and without salt.
- **Password Security**: Argon2 hashing for secure password storage and validation.
- **Encryption & Decryption**: AES for symmetric encryption and RSA for asymmetric encryption.
- **JWT**: Generates token signed with private key and validates with public key.


## Usage

### Hashing
```java
String hash = HashUtils.sha256("mySecureData");
String hashWithSalt = HashUtils.sha256Salt("mySecureData", HashUtils.getSalt());
```

### Password Security
```java
byte[] salt = PasswordsUtils.generateSalt();
String hashedPassword = PasswordsUtils.hashPassword("myPassword", salt);
boolean isValid = PasswordsUtils.validatePassword("myPassword", hashedPassword);
```

## Roadmap
- [x] Hashing utilities (SHA-256, SHA-512)
- [x] Secure password storage (Argon2)
- [x] AES encryption & decryption (WIP)
- [x] RSA encryption & signing (WIP)
- [x] JWT - Generate token with expiration time

## Contributing
Feel free to contribute by submitting issues or pull requests. Any security improvements or additional cryptographic features are welcome!

## License
This project is licensed under the MIT License.

