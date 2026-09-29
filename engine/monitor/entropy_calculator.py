import math
from typing import Union, BinaryIO

class EntropyCalculator:
    """
    Computes Shannon Entropy and byte-distribution statistics for fast ransomware encryption detection.
    Shannon Entropy ranges from 0.0 (uniform/zero randomness) to 8.0 (maximum randomness / encrypted / compressed).
    """

    @staticmethod
    def calculate_bytes_entropy(data: bytes) -> float:
        """
        Calculates Shannon Entropy of a byte buffer.
        H = - sum(p(x) * log2(p(x)))
        """
        if not data:
            return 0.0

        length = len(data)
        byte_counts = [0] * 256
        for b in data:
            byte_counts[b] += 1

        entropy = 0.0
        for count in byte_counts:
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)

        return round(entropy, 4)

    @staticmethod
    def calculate_file_entropy(file_path: str, sample_size: int = 65536) -> float:
        """
        Calculates entropy of a file by sampling up to sample_size bytes.
        Fast and non-blocking for large files.
        """
        try:
            with open(file_path, 'rb') as f:
                data = f.read(sample_size)
                if not data:
                    return 0.0
                return EntropyCalculator.calculate_bytes_entropy(data)
        except (PermissionError, FileNotFoundError, OSError):
            return 0.0

    @staticmethod
    def is_likely_encrypted(entropy: float, threshold: float = 7.55) -> bool:
        """
        Checks if the entropy value indicates strong encryption or high-density compression.
        Standard text files: ~3.5 - 5.0
        Code/HTML: ~4.5 - 5.5
        Executable/DLLs: ~6.0 - 6.8
        Zip/PNG/JPEG: ~7.2 - 7.7
        AES / RSA / ChaCha20 Encrypted Ransomware output: ~7.75 - 7.999
        """
        return entropy >= threshold

    @staticmethod
    def calculate_chi_square(data: bytes) -> float:
        """
        Calculates Chi-Square distribution for byte randomness.
        In truly encrypted data, byte distribution is uniformly flat.
        """
        if not data:
            return 0.0
        length = len(data)
        expected = length / 256.0
        byte_counts = [0] * 256
        for b in data:
            byte_counts[b] += 1

        chi_sq = sum(((count - expected) ** 2) / expected for count in byte_counts)
        return round(chi_sq, 2)
