# QR Stego Secure

This tool securely hides encrypted messages inside QR codes using AES encryption and LSB steganography. The visible QR contains a decoy message, while the real message is hidden inside the image.

## 🚀 Features

- 🔐 AES-256-CBC encryption using passphrase
- 🖼️ LSB-based steganography to embed encrypted data in QR code images
- 🪄 Automatically generated **decoy messages** for QR readability
- ✅ Safe offline encryption/decryption
- 🧹 Optionally wipe hidden data after decoding

---
## 🔧 Installation

```bash
pip install .
```

Install from PyPI:

```bash
pip install qr-stego-secure
```
## Usage

### Encode a secret message:
```
qr-stego --encode --message "Secret123" --passphrase "myp@ss" --image "secret_qr.png"
```

### Decode a secret message:
```
qr-stego --decode --passphrase "myp@ss" --image "secret_qr.png"
```