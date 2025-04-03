# SecurityUtils

SecurityUtils is a Java utility library that provides essential cryptographic functions, including hashing, password security, and encryption/decryption mechanisms. It is designed to simplify security-related operations in Java applications.

## Features
- **Hashing Algorithms**: SHA-256 and SHA-512 with and without salt.
- **Password Security**: PBKDF2-based hashing for secure password storage and validation.
- **Encryption & Decryption**: AES for symmetric encryption and RSA for asymmetric encryption (Coming soon).

## Installation

You can include SecurityUtils in your project using Maven:

```xml
<dependency>
    <groupId>com.yourcompany</groupId>
    <artifactId>security-utils</artifactId>
    <version>1.0.0</version>
</dependency>
```

Or with Gradle:

```gradle
dependencies {
    implementation 'com.yourcompany:security-utils:1.0.0'
}
```

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

## Contributing
Feel free to contribute by submitting issues or pull requests. Any security improvements or additional cryptographic features are welcome!

## License
This project is licensed under the MIT License.

