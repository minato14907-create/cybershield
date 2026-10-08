import base64
import hashlib
import os
from dataclasses import dataclass


@dataclass
class EncryptionResult:
    algorithm: str
    ciphertext: str
    key: str
    iv: Optional[str] = None
    mode: str = ""


class EncryptionSuite:
    def __init__(self):
        try:
            from cryptography.hazmat.primitives.ciphers import algorithms, modes
            from cryptography.hazmat.primitives import padding as sym_padding
            self._available = True
        except ImportError:
            self._available = False

    def aes_encrypt(self, plaintext: str, key: bytes = None) -> dict:
        if not self._available:
            raise ImportError("cryptography is required")

        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives import padding as sym_padding

        if key is None:
            key = os.urandom(32)
        iv = os.urandom(16)

        padder = sym_padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext.encode()) + padder.finalize()

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        return {
            "algorithm": "AES-256-CBC",
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "key": base64.b64encode(key).decode(),
            "iv": base64.b64encode(iv).decode(),
            "mode": "CBC",
        }

    def aes_decrypt(self, ciphertext_b64: str, key_b64: str, iv_b64: str) -> str:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives import padding as sym_padding

        key = base64.b64decode(key_b64)
        iv = base64.b64decode(iv_b64)
        ciphertext = base64.b64decode(ciphertext_b64)

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = sym_padding.PKCS7(128).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()

        return data.decode()

    def rsa_encrypt(self, plaintext: str) -> dict:
        from cryptography.hazmat.primitives.asymmetric import rsa, padding
        from cryptography.hazmat.primitives import hashes, serialization

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        public_key = private_key.public_key()

        ciphertext = public_key.encrypt(
            plaintext.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        return {
            "algorithm": "RSA-2048-OAEP",
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "private_key": private_pem.decode(),
            "mode": "OAEP",
        }

    def rsa_decrypt(self, ciphertext_b64: str, private_key_pem: str) -> str:
        from cryptography.hazmat.primitives.asymmetric import rsa, padding
        from cryptography.hazmat.primitives import hashes, serialization

        private_key = serialization.load_pem_private_key(
            private_key_pem.encode(), password=None
        )

        plaintext = private_key.decrypt(
            base64.b64decode(ciphertext_b64),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        return plaintext.decode()

    @staticmethod
    def caesar_cipher(text: str, shift: int, decrypt: bool = False) -> str:
        if decrypt:
            shift = -shift
        result = []
        for char in text:
            if char.isalpha():
                base = ord("A") if char.isupper() else ord("a")
                result.append(chr((ord(char) - base + shift) % 26 + base))
            else:
                result.append(char)
        return "".join(result)

    @staticmethod
    def vigenere_cipher(text: str, key: str, decrypt: bool = False) -> str:
        result = []
        key_index = 0
        key = key.lower()

        for char in text:
            if char.isalpha():
                base = ord("A") if char.isupper() else ord("a")
                shift = ord(key[key_index % len(key)]) - ord("a")
                if decrypt:
                    shift = -shift
                result.append(chr((ord(char) - base + shift) % 26 + base))
                key_index += 1
            else:
                result.append(char)

        return "".join(result)

    @staticmethod
    def xor_cipher(text: str, key: str) -> str:
        result = []
        for i, char in enumerate(text):
            result.append(chr(ord(char) ^ ord(key[i % len(key)])))
        return "".join(result)

    @staticmethod
    def hash_text(text: str, algorithm: str = "sha256") -> str:
        algorithms_map = {
            "md5": hashlib.md5,
            "sha1": hashlib.sha1,
            "sha256": hashlib.sha256,
            "sha512": hashlib.sha512,
        }
        hasher = algorithms_map.get(algorithm, hashlib.sha256)
        return hasher(text.encode()).hexdigest()


if __name__ == "__main__":
    suite = EncryptionSuite()

    print("=== Caesar Cipher ===")
    encrypted = suite.caesar_cipher("Hello World", 3)
    decrypted = suite.caesar_cipher(encrypted, 3, decrypt=True)
    print(f"Original:  Hello World")
    print(f"Encrypted: {encrypted}")
    print(f"Decrypted: {decrypted}")

    print("\n=== Vigenere Cipher ===")
    encrypted = suite.vigenere_cipher("Hello World", "KEY")
    decrypted = suite.vigenere_cipher(encrypted, "KEY", decrypt=True)
    print(f"Original:  Hello World")
    print(f"Encrypted: {encrypted}")
    print(f"Decrypted: {decrypted}")

    print("\n=== Hashing ===")
    for algo in ["md5", "sha256"]:
        print(f"{algo.upper()}: {suite.hash_text('Hello World', algo)}")
