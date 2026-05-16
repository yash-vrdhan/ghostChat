import base64

from nacl.public import Box, PrivateKey, PublicKey


def encrypt_message(sender_private_key: PrivateKey, recipient_public_key: PublicKey, plaintext: str) -> str:
    box = Box(sender_private_key, recipient_public_key)
    encrypted = box.encrypt(plaintext.encode("utf-8"))
    return base64.b64encode(encrypted).decode("ascii")


def decrypt_message(receiver_private_key: PrivateKey, sender_public_key: PublicKey, ciphertext_b64: str) -> str:
    box = Box(receiver_private_key, sender_public_key)
    encrypted = base64.b64decode(ciphertext_b64)
    plaintext = box.decrypt(encrypted)
    return plaintext.decode("utf-8")
