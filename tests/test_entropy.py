import secrets
from engine.monitor.entropy_calculator import EntropyCalculator

def test_plain_text_entropy():
    plain_text = b"This is a standard confidential corporate quarterly revenue financial report for audit."
    entropy = EntropyCalculator.calculate_bytes_entropy(plain_text)
    assert entropy < 5.0, f"Expected low entropy for text, got {entropy}"
    assert not EntropyCalculator.is_likely_encrypted(entropy)

def test_encrypted_bytes_entropy():
    # 4KB of crypto-grade random bytes (simulating AES-256 / ChaCha20 ciphertext)
    encrypted_payload = secrets.token_bytes(4096)
    entropy = EntropyCalculator.calculate_bytes_entropy(encrypted_payload)
    assert entropy >= 7.8, f"Expected high entropy for encrypted data (>7.8), got {entropy}"
    assert EntropyCalculator.is_likely_encrypted(entropy)
