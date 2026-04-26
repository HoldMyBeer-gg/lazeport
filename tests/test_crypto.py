import pytest

from app.services.crypto import decrypt_text, encrypt_text


def test_encrypt_decrypt_roundtrip():
    plaintext = "secret-data"
    ciphertext = encrypt_text(plaintext)
    assert ciphertext != plaintext
    assert decrypt_text(ciphertext) == plaintext


def test_encrypt_decrypt_empty_string():
    """Empty string round-trips correctly."""
    plaintext = ""
    ciphertext = encrypt_text(plaintext)
    assert ciphertext != plaintext
    assert decrypt_text(ciphertext) == plaintext


def test_encrypt_produces_different_ciphertext():
    """Same plaintext produces different ciphertext each time (nonce/IV)."""
    plaintext = "same-secret"
    c1 = encrypt_text(plaintext)
    c2 = encrypt_text(plaintext)
    assert c1 != c2
    assert decrypt_text(c1) == plaintext
    assert decrypt_text(c2) == plaintext


def test_decrypt_invalid_ciphertext_raises():
    """Invalid or tampered ciphertext raises an exception."""
    with pytest.raises(Exception):
        decrypt_text("not-valid-ciphertext")
    with pytest.raises(Exception):
        decrypt_text("")
