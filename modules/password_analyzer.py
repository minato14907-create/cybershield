import math
import re
import hashlib
from dataclasses import dataclass


@dataclass
class PasswordReport:
    password: str
    score: int
    strength: str
    crack_time: str
    feedback: list[str]
    entropy: float
    has_upper: bool
    has_lower: bool
    has_digit: bool
    has_special: bool
    length: int
    breach_count: int = 0


class PasswordAnalyzer:
    COMMON_PASSWORDS = {
        "password", "123456", "12345678", "qwerty", "abc123",
        "monkey", "master", "dragon", "login", "princess",
        "football", "shadow", "sunshine", "trustno1", "iloveyou",
        "batman", "access", "hello", "charlie", "password1",
    }

    def __init__(self):
        try:
            import zxcvbn as _zxcvbn
            self._zxcvbn = _zxcvbn
        except ImportError:
            self._zxcvbn = None

    def analyze(self, password: str) -> PasswordReport:
        score, crack_time, feedback = self._zxcvbn_analysis(password)
        entropy = self._calculate_entropy(password)

        return PasswordReport(
            password="*" * len(password),
            score=score,
            strength=self._score_to_label(score),
            crack_time=crack_time,
            feedback=feedback,
            entropy=entropy,
            has_upper=bool(re.search(r"[A-Z]", password)),
            has_lower=bool(re.search(r"[a-z]", password)),
            has_digit=bool(re.search(r"\d", password)),
            has_special=bool(re.search(r"[!@#$%^&*(),.?\":{}|<>]", password)),
            length=len(password),
            breach_count=self._check_common(password),
        )

    def _zxcvbn_analysis(self, password: str) -> tuple:
        if self._zxcvbn:
            result = self._zxcvbn.zxcvbn(password)
            score = result["score"]
            crack_time = result["crack_times_display"]["offline_slow_hashing_1e4_per_second"]
            feedback = []
            if result["feedback"]["warning"]:
                feedback.append(result["feedback"]["warning"])
            feedback.extend(result["feedback"]["suggestions"])
            return score, crack_time, feedback

        score = 0
        feedback = []

        if len(password) >= 8:
            score += 1
        if len(password) >= 12:
            score += 1
        if re.search(r"[A-Z]", password) and re.search(r"[a-z]", password):
            score += 1
        if re.search(r"\d", password):
            score += 1
        if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            score += 1

        score = min(score, 4)

        if len(password) < 8:
            feedback.append("Use at least 8 characters")
        if not re.search(r"[A-Z]", password):
            feedback.append("Add uppercase letters")
        if not re.search(r"\d", password):
            feedback.append("Add numbers")
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            feedback.append("Add special characters")

        crack_time = self._estimate_crack_time(password, score)
        return score, crack_time, feedback

    def _calculate_entropy(self, password: str) -> float:
        charset_size = 0
        if re.search(r"[a-z]", password):
            charset_size += 26
        if re.search(r"[A-Z]", password):
            charset_size += 26
        if re.search(r"\d", password):
            charset_size += 10
        if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            charset_size += 32

        if charset_size == 0:
            return 0.0

        return len(password) * math.log2(charset_size)

    def _estimate_crack_time(self, password: str, score: int) -> str:
        charset_size = 0
        if re.search(r"[a-z]", password):
            charset_size += 26
        if re.search(r"[A-Z]", password):
            charset_size += 26
        if re.search(r"\d", password):
            charset_size += 10
        if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            charset_size += 32

        if charset_size == 0:
            return "Instantly"

        combinations = charset_size ** len(password)
        guesses_per_second = 10000
        seconds = combinations / guesses_per_second

        if seconds < 1:
            return "Instantly"
        elif seconds < 60:
            return f"{seconds:.0f} seconds"
        elif seconds < 3600:
            return f"{seconds / 60:.0f} minutes"
        elif seconds < 86400:
            return f"{seconds / 3600:.0f} hours"
        elif seconds < 31536000:
            return f"{seconds / 86400:.0f} days"
        else:
            years = seconds / 31536000
            if years > 1e9:
                return f"{years:.2e} years"
            return f"{years:,.0f} years"

    def _score_to_label(self, score: int) -> str:
        labels = {0: "Very Weak", 1: "Weak", 2: "Fair", 3: "Strong", 4: "Very Strong"}
        return labels.get(score, "Unknown")

    def _check_common(self, password: str) -> int:
        if password.lower() in self.COMMON_PASSWORDS:
            return 999999
        return 0

    def generate_report(self, password: str) -> dict:
        report = self.analyze(password)
        return {
            "password_length": report.length,
            "score": report.score,
            "strength": report.strength,
            "crack_time": report.crack_time,
            "entropy_bits": round(report.entropy, 2),
            "has_uppercase": report.has_upper,
            "has_lowercase": report.has_lower,
            "has_numbers": report.has_digit,
            "has_special": report.has_special,
            "feedback": report.feedback,
            "is_common": report.breach_count > 0,
        }


if __name__ == "__main__":
    analyzer = PasswordAnalyzer()
    test_passwords = ["password", "P@ssw0rd!", "MyStr0ng!Pass#2024", "a"]

    for pwd in test_passwords:
        report = analyzer.analyze(pwd)
        print(f"\n{'='*40}")
        print(f"Password: {report.password}")
        print(f"Strength: {report.strength} ({report.score}/4)")
        print(f"Crack Time: {report.crack_time}")
        print(f"Entropy: {report.entropy:.2f} bits")
        if report.feedback:
            print(f"Feedback: {', '.join(report.feedback)}")
