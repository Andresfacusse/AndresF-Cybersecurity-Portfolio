import secrets
import string
import re

class PasswordGenerator:
    def __init__(self):
        self.lowercase = string.ascii_lowercase
        self.uppercase = string.ascii_uppercase
        self.digits = string.digits
        self.symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?"

    def generate_password(self, length=12, include_uppercase=True, include_lowercase=True, include_digits=True, include_symbols=True, min_uppercase=1, min_lowercase=1, min_digits=1, min_symbols=1):
        # Validate input parameters
        if length < 4:
            raise ValueError("Password length must be at least 4 characters")
        # Build character pool
        char_pool = ""
        guaranteed_chars = []
        if include_lowercase:
            char_pool += self.lowercase
            guaranteed_chars.extend(secrets.choice(self.lowercase) for _ in range(min_lowercase))
        if include_uppercase:
            char_pool += self.uppercase
            guaranteed_chars.extend(secrets.choice(self.uppercase) for _ in range(min_uppercase))
        if include_digits:
            char_pool += self.digits
            guaranteed_chars.extend(secrets.choice(self.digits) for _ in range(min_digits))
        if include_symbols:
            char_pool += self.symbols
            guaranteed_chars.extend(secrets.choice(self.symbols) for _ in range(min_symbols))
        if not char_pool:
            raise ValueError("At least one character type must be enabled")
        # Calculate remaining characters needed
        remaining_length = length - len(guaranteed_chars)
        if remaining_length < 0:
            raise ValueError("Password length too short for minimum requirements")
        # Generate remaining characters
        additional_chars = [secrets.choice(char_pool) for _ in range(remaining_length)]
        # Combine and shuffle all characters
        all_chars = guaranteed_chars + additional_chars
        password_list = list(all_chars)
        # Secure shuffle using secrets module
        for i in range(len(password_list) - 1, 0, -1):
            j = secrets.randbelow(i + 1)
            password_list[i], password_list[j] = password_list[j], password_list[i]
        return ''.join(password_list)

    def validate_password_strength(self, password):
        score = 0
        feedback = []
        # Length check
        if len(password) >= 12:
            score += 2
        elif len(password) >= 8:
            score += 1
        else:
            feedback.append("Consider using at least 8 characters")
        # Character type checks
        if re.search(r'[a-z]', password):
            score += 1
        else:
            feedback.append("Add lowercase letters")
        if re.search(r'[A-Z]', password):
            score += 1
        else:
            feedback.append("Add uppercase letters")
        if re.search(r'\d', password):
            score += 1
        else:
            feedback.append("Add numbers")
        if re.search(r'[!@#$%^&*()_+\\-=[\]{}|;:,.<>?]', password):
            score += 1
        else:
            feedback.append("Add special characters")
        # Determine overall strength
        if score >= 6:
            strength = "Strong"
        elif score >= 4:
            strength = "Moderate"
        else:
            strength = "Weak"
        return {"strength": strength, "score": score, "feedback": feedback}   
