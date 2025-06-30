# 🔐 SecureMessenger-RSA

A lightweight C#/.NET command-line tool for sending and receiving encrypted messages using RSA public-key cryptography. It supports key generation, key exchange with a central server, and secure message communication between users via email identifiers.

## 🧠 Features

- RSA-based asymmetric encryption
- Custom key generation with configurable size
- Public/private key serialization and local storage
- Email-based key distribution (via HTTP PUT/GET to remote server)
- Secure message encryption and decryption
- Miller-Rabin primality testing for efficient large-prime generation
- Support for multiple recipients and incoming message handling

## 🚀 Getting Started

### ⚙️ Requirements

- [.NET SDK](https://dotnet.microsoft.com/en-us/download) 
- Internet connection (to communicate with the key/message server)

### 📦 Build

```
dotnet build
```

### ▶️ Usage
```
dotnet run <command> [args]
```

### 🧾 Command Usage
| Command                       | Description                                                       |
| ----------------------------- | ----------------------------------------------------------------- |
| `keyGen <keySize>`            | Generate RSA key pair of size `<keySize>` (must be multiple of 8) |
| `sendKey <email>`             | Attach your email and send your public key to the server          |
| `getKey <email>`              | Fetch and locally store the public key of a user                  |
| `sendMsg <email> <plaintext>` | Encrypt and send a message to a user using their public key       |
| `getMsg <email>`              | Retrieve and decrypt your message using your private key          |

### Example
```
dotnet run keyGen 512
dotnet run sendKey alice@example.com
dotnet run getKey bob@example.com
dotnet run sendMsg bob@example.com "Hello Bob!"
dotnet run getMsg alice@example.com
```

### 🧠 Behind the Scenes

- **Primality Testing**: Miller-Rabin probabilistic test
- **Encryption**: RSA using `BigInteger.ModPow`
- **Parallelization**: Multi-threaded prime number generation
- **Key Format**: Encoded as length-prefixed Base64 byte arrays
