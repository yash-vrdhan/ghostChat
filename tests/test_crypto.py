from ghostchat.crypto.encrypt import decrypt_message, encrypt_message
from ghostchat.crypto.signing import sign_message, verify_signature
from nacl.public import PrivateKey
from nacl.signing import SigningKey


def test_encrypt_decrypt_round_trip() -> None:
    alice = PrivateKey.generate()
    bob = PrivateKey.generate()
    text = "hello bob"
    ciphertext = encrypt_message(alice, bob.public_key, text)
    result = decrypt_message(bob, alice.public_key, ciphertext)
    assert result == text


def test_sign_verify_round_trip() -> None:
    sk = SigningKey.generate()
    vk = sk.verify_key
    text = "integrity"
    sig = sign_message(sk, text)
    assert verify_signature(vk, text, sig) is True
    assert verify_signature(vk, "tampered", sig) is False
