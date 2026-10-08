import hashlib
import itertools
import string
import time
from dataclasses import dataclass
from typing import Optional


@dataclass
class CrackResult:
    hash_value: str
    algorithm: str
    cracked: bool
    plaintext: Optional[str] = None
    time_taken: float = 0.0
    attempts: int = 0


class HashCracker:
    COMMON_WORDS = [
        "password", "123456", "12345678", "qwerty", "abc123",
        "monkey", "master", "dragon", "login", "princess",
        "football", "shadow", "sunshine", "trustno1", "iloveyou",
        "batman", "access", "hello", "charlie", "password1",
        "admin", "letmein", "welcome", "summer", "winter",
        "spring", "autumn", "computer", "internet", "school",
        "google", "facebook", "amazon", "microsoft", "apple",
        "test", "user", "guest", "root", "toor",
        "pass", "secret", "love", "sex", "god",
    ]

    def __init__(self):
        self.algorithms = {
            "md5": hashlib.md5,
            "sha1": hashlib.sha1,
            "sha256": hashlib.sha256,
            "sha512": hashlib.sha512,
        }

    def identify_hash(self, hash_value: str) -> str:
        length = len(hash_value)
        if length == 32:
            return "md5"
        elif length == 40:
            return "sha1"
        elif length == 64:
            return "sha256"
        elif length == 128:
            return "sha512"
        return "unknown"

    def _hash_with_algorithm(self, text: str, algorithm: str) -> str:
        hasher = self.algorithms.get(algorithm, hashlib.sha256)
        return hasher(text.encode()).hexdigest()

    def dictionary_attack(self, hash_value: str, algorithm: str,
                          wordlist: Optional[list[str]] = None) -> CrackResult:
        words = wordlist or self.COMMON_WORDS
        start_time = time.time()
        attempts = 0

        for word in words:
            attempts += 1
            if self._hash_with_algorithm(word, algorithm) == hash_value:
                return CrackResult(
                    hash_value=hash_value,
                    algorithm=algorithm,
                    cracked=True,
                    plaintext=word,
                    time_taken=time.time() - start_time,
                    attempts=attempts,
                )

        return CrackResult(
            hash_value=hash_value,
            algorithm=algorithm,
            cracked=False,
            time_taken=time.time() - start_time,
            attempts=attempts,
        )

    def brute_force(self, hash_value: str, algorithm: str,
                    max_length: int = 4,
                    charset: str = string.ascii_lowercase + string.digits) -> CrackResult:
        start_time = time.time()
        attempts = 0

        for length in range(1, max_length + 1):
            for combination in itertools.product(charset, repeat=length):
                attempts += 1
                candidate = "".join(combination)
                if self._hash_with_algorithm(candidate, algorithm) == hash_value:
                    return CrackResult(
                        hash_value=hash_value,
                        algorithm=algorithm,
                        cracked=True,
                        plaintext=candidate,
                        time_taken=time.time() - start_time,
                        attempts=attempts,
                    )

        return CrackResult(
            hash_value=hash_value,
            algorithm=algorithm,
            cracked=False,
            time_taken=time.time() - start_time,
            attempts=attempts,
        )

    def rainbow_table_demo(self, algorithm: str = "md5") -> dict:
        table = {}
        for word in self.COMMON_WORDS[:20]:
            hashed = self._hash_with_algorithm(word, algorithm)
            table[hashed] = word
        return table

    def compare_hashes(self, text: str) -> dict:
        results = {}
        for algo_name, algo_func in self.algorithms.items():
            results[algo_name] = algo_func(text.encode()).hexdigest()
        return results

    def to_json(self, result: CrackResult) -> str:
        import json
        return json.dumps({
            "hash": result.hash_value,
            "algorithm": result.algorithm,
            "cracked": result.cracked,
            "plaintext": result.plaintext,
            "time_seconds": round(result.time_taken, 4),
            "attempts": result.attempts,
        }, indent=2)


if __name__ == "__main__":
    cracker = HashCracker()

    test_text = "hello"
    print("=== Hash Comparison ===")
    hashes = cracker.compare_hashes(test_text)
    for algo, h in hashes.items():
        print(f"  {algo.upper()}: {h}")

    print("\n=== Dictionary Attack ===")
    target = cracker._hash_with_algorithm("password", "md5")
    print(f"Target hash (md5 of 'password'): {target}")
    result = cracker.dictionary_attack(target, "md5")
    print(f"Cracked: {result.cracked}, Text: {result.plaintext}")
    print(f"Attempts: {result.attempts}, Time: {result.time_taken:.4f}s")

    print("\n=== Rainbow Table Demo ===")
    table = cracker.rainbow_table_demo("md5")
    for h, word in list(table.items())[:5]:
        print(f"  {h} -> {word}")
