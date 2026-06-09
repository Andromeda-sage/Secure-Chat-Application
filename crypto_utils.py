import os
import base64

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ==========================
# RSA KEY GENERATION
# ==========================
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    return private_key, private_key.public_key()


# ==========================
# SERIALIZE PUBLIC KEY
# ==========================
def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()


# ==========================
# LOAD PUBLIC KEY
# ==========================
def load_public_key(pem_str):
    return serialization.load_pem_public_key(
        pem_str.encode()
    )


# ==========================
# RSA ENCRYPT AES KEY
# ==========================
def encrypt_aes_key(public_key, aes_key):
    return public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


# ==========================
# RSA DECRYPT AES KEY
# ==========================
def decrypt_aes_key(private_key, encrypted_key):
    return private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


# ==========================
# AES-GCM ENCRYPT MESSAGE
# ==========================
def encrypt_message(message, aes_key):
    aesgcm = AESGCM(aes_key)

    nonce = os.urandom(12)

    ciphertext = aesgcm.encrypt(
        nonce,
        message.encode(),
        None
    )

    return nonce, ciphertext


# ==========================
# AES-GCM DECRYPT MESSAGE
# ==========================
def decrypt_message(nonce, ciphertext, aes_key):
    aesgcm = AESGCM(aes_key)

    return aesgcm.decrypt(
        nonce,
        ciphertext,
        None
    ).decode()


# ==========================
# SIGN MESSAGE (RSA-PSS)
# ==========================
def sign_message(private_key, message):
    return private_key.sign(
        message.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )


# ==========================
# VERIFY SIGNATURE
# ==========================
def verify_signature(public_key, message, signature):
    try:
        public_key.verify(
            signature,
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True

    except Exception:
        return False