import os
import base64
import hashlib
import random
import qrcode
from PIL import Image
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import yaml
import pkgutil

# =========================
# AES Encryption with Passphrase
# =========================

def derive_key(passphrase: str) -> bytes:
    return hashlib.sha256(passphrase.encode()).digest()

def encrypt_message(message: str, passphrase: str) -> str:
    key = derive_key(passphrase)
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(message.encode()) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encrypted = cipher.encryptor().update(padded) + cipher.encryptor().finalize()
    return base64.b64encode(iv + encrypted).decode()

def decrypt_message(encrypted_b64: str, passphrase: str) -> str:
    key = derive_key(passphrase)
    raw = base64.b64decode(encrypted_b64)
    iv = raw[:16]
    encrypted = raw[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decrypted = cipher.decryptor().update(encrypted) + cipher.decryptor().finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(decrypted) + unpadder.finalize()

# =========================
# LSB Steganography
# =========================

EOF_MARKER = '1111111111111110'

def hide_data_in_image(image_path, output_path, secret_data):
    img = Image.open(image_path)
    img = img.convert('RGB')
    binary = ''.join(format(ord(char), '08b') for char in secret_data) + EOF_MARKER
    pixels = list(img.getdata())
    data_index = 0
    new_pixels = []

    for pixel in pixels:
        r, g, b = pixel
        if data_index < len(binary):
            r = (r & ~1) | int(binary[data_index])
            data_index += 1
        if data_index < len(binary):
            g = (g & ~1) | int(binary[data_index])
            data_index += 1
        if data_index < len(binary):
            b = (b & ~1) | int(binary[data_index])
            data_index += 1
        new_pixels.append((r, g, b))

    img.putdata(new_pixels)
    img.save(output_path)
    print(f"[+] Hidden data saved to: {output_path}")

def extract_data_from_image(image_path):
    img = Image.open(image_path)
    img = img.convert('RGB')
    binary = ''
    for pixel in img.getdata():
        for channel in pixel:
            binary += str(channel & 1)

    # Search for EOF marker in binary
    eof_index = binary.find('1111111111111110')
    if eof_index == -1:
        raise ValueError("EOF marker not found. Possibly not a valid stego image.")

    # Only use data up to EOF marker
    binary = binary[:eof_index]

    # Convert binary to characters
    all_bytes = [binary[i:i+8] for i in range(0, len(binary), 8)]
    decoded_bytes = bytearray([int(byte, 2) for byte in all_bytes])
    try:
        return decoded_bytes.decode('utf-8')  # Encrypted data is base64 and safe to decode
    except UnicodeDecodeError:
        raise ValueError("Failed to decode hidden data. It may be corrupted.")


# =========================
# QR Code with Decoy Generator
# =========================
def load_templates_from_package():
    try:
        raw_data = pkgutil.get_data(__package__, 'data/decoy_templates.yaml')
        return yaml.safe_load(raw_data)
    except Exception as e:
        print(f"[x] Failed to load template file: {e}")
        return ["Scan now to claim your ₹{amount} reward!"]
    
def generate_decoy_message():
    templates_data = load_templates_from_package()

    if isinstance(templates_data, dict):
        all_templates = [tpl for group in templates_data.values() for tpl in group]
    elif isinstance(templates_data, list):
        all_templates = templates_data
    else:
        all_templates = ["Scan now to claim your ₹{amount} reward!"]

    template = random.choice(all_templates)
    return template.format(
        amount=random.randint(50, 1000),
        code=''.join(random.choices('ABCDEFGHJKLMNPQRSTUVWXYZ23456789', k=6))
    )



def create_qr_code(message: str, path: str):
    qr = qrcode.QRCode(version=4, error_correction=qrcode.constants.ERROR_CORRECT_H, box_size=10, border=4)
    qr.add_data(message)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white").convert("RGB")
    img.save(path)

# =========================
# Entry Point: Encode
# =========================

def encode_secret_to_qr(secret_message: str, passphrase: str, output_image: str, decoy_message: str = None):
    encrypted = encrypt_message(secret_message, passphrase)
    decoy = decoy_message if decoy_message else generate_decoy_message()
    print(f"[+] Using decoy message: {decoy}")
    qr_path = "temp_qr.png"
    create_qr_code(decoy, qr_path)
    hide_data_in_image(qr_path, output_image, encrypted)
    os.remove(qr_path)
    print("[+] QR Code with hidden data generated.")

# =========================
# Entry Point: Decode
# =========================

def decode_secret_from_qr(image_path: str, passphrase: str):
    extracted_encrypted = extract_data_from_image(image_path)
    try:
        decrypted = decrypt_message(extracted_encrypted, passphrase)
        print("[✓] Secret message found:")
        print(decrypted)
    except Exception as e:
        print("[x] Decryption failed. Possibly wrong passphrase or tampered image.")
        print("Error:", str(e))


def wipe_hidden_data(image_path: str):
    img = Image.open(image_path)
    img = img.convert("RGB")
    pixels = list(img.getdata())

    # Overwrite only up to the first EOF marker worth of bits
    bits_to_wipe = 8000  # Adjust based on max expected size (1000 bytes → 8000 bits)
    new_pixels = []
    bit_index = 0

    for pixel in pixels:
        r, g, b = pixel
        if bit_index < bits_to_wipe:
            r = r & ~1
            bit_index += 1
        if bit_index < bits_to_wipe:
            g = g & ~1
            bit_index += 1
        if bit_index < bits_to_wipe:
            b = b & ~1
            bit_index += 1
        new_pixels.append((r, g, b))

    img.putdata(new_pixels)
    img.save(image_path)
    print("[!] Hidden data has been wiped after decryption.")

# =========================
# Demo: Run from Main
# =========================

def main():
    import argparse

    parser = argparse.ArgumentParser(description="QR Stego Secure Encoder/Decoder")
    parser.add_argument('--encode', action='store_true', help="Encode a secret message")
    parser.add_argument('--decode', action='store_true', help="Decode a hidden message from QR")
    parser.add_argument('--message', type=str, help="Secret message to encode")
    parser.add_argument('--passphrase', type=str, required=True, help="Passphrase for encryption/decryption")
    parser.add_argument('--image', type=str, help="Path to QR image (for decode) or output image (for encode)")
    parser.add_argument('--decoy', type=str, help="Optional custom decoy message")

    args = parser.parse_args()

    if args.encode:
        if not args.message or not args.image:
            print("Encoding requires --message and --image")
        else:
            encode_secret_to_qr(args.message, args.passphrase, args.image, args.decoy)

    elif args.decode:
        if not args.image:
            print("Decoding requires --image")
        else:
            decode_secret_from_qr(args.image, args.passphrase)

if __name__ == "__main__":
    main()