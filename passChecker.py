import re
import requests
import json
import math
from typing import List
import hashlib
import argparse

class PassChecker:
    CONFIG_FILE_NAME: str = "config.json"
    REGEXES_PATTERNS: List[str] = [
        r'[A-Z]',
        r'[a-z]',
        r'[0-9]',
        r'[@#$%^&+=!(){}[\]:;<>,.?/~_+\-|]'
    ]
    PASSWORD_STRENGTH_LEVELS = [
        "Extremely Weak",
        "Very Weak",
        "Weak",
        "Medium",
        "Strong",
        "Very Strong"
    ]
    HIBP_API_URL = "https://api.pwnedpasswords.com/range"
    HIBP_HEADER = "hibp-api-key"
    
    PASSWORD_MIN_LENGTH_LEVEL_1 = 6
    PASSWORD_MIN_LENGTH_LEVEL_2 = 8
    PASSWORD_MIN_LENGTH_LEVEL_3 = 10
    PASSWORD_MIN_LENGTH_LEVEL_4 = 12
    PASSWORD_MIN_LENGTH_LEVEL_5 = 14

    REGEX_PATTERN_REQUIREMENT_LEVEL_2 = 2
    REGEX_PATTERN_REQUIREMENT_LEVEL_3 = 3

    REPETITIVE_CHAR_THRESHOLD_LEVEL_4 = 4
    REPETITIVE_CHAR_THRESHOLD_LEVEL_5 = 3

    SEQUENTIAL_CHAR_THRESHOLD_LEVEL_4 = 4
    SEQUENTIAL_CHAR_THRESHOLD_LEVEL_5 = 3
    
    ENTROPY_THRESHOLD_LEVEL_5 = 3.55
    
    def __init__(self, password: str, username: str = None):
        """
        Initialize a new instance of the PassChecker class.
        Args:
            password (str): The password to be checked. Must not be empty.
            username (str, optional): The username associated with the password. Defaults to None.
        Raises:
            ValueError: If the password is empty.
        """
        
        if not password:
            raise ValueError("Password cannot be empty.")
        
        self.password = password
        self.username = username
        self.point = 0
        self.reason = ""
        
    # [START] Private Helper methods
        
    def __incrementPoint(self) -> None:
        """
        Increments the point attribute by 1.
        """
        
        self.point += 1
        
    def __isRepetitive(self, threshold: int) -> bool:
        """
        Check if the password is repetitive based on given threshold.
        This method checks if the password contains repetitive patterns that 
        make it weak. It performs the following checks:
        1. If the password consists of only one character.
        2. If the password contains joined repetitive characters.
        3. If the password contains sparse repetitive substrings.
        Args:
            threshold (int): The threshold for considering a substring as repetitive. 
            
        Returns:
            bool: True if the password is considered repetitive, False otherwise.
        """
        
        if len(set(self.password)) == 1:
            self.reason = "Password contains only one character"
            return True
        
        match = re.search(r"(.{2,})\1+", self.password)
        if match and len(self.password) // len(match.group(1)) >= threshold:
            self.reason = "Password contains joined repetitive characters"
            return True

        substrings = {
            self.password[i:j]
            for i in range(len(self.password))
            for j in range(i + 2, len(self.password) + 1)
        }       
        
        for substring in substrings:
            count = len(re.findall(re.escape(substring), self.password))
            if count >= threshold:
                self.reason = f"Password contains repetitive substring: {substring} ({count} occurrences)"
                return True
        return False
    
    def __isPalindrome(self) -> bool:
        """
        Check if the password is a palindrome.
        A palindrome is a string that reads the same forward and backward.

        Returns:
            bool: True if the password is a palindrome, False otherwise.
        """
        
        if self.password == self.password[::-1]:
            self.reason = "Password is a palindrome"
            return True
        return False 
    
    def __containsUsername(self) -> bool:
        """
        Checks if the password contains the username.

        Returns:
            bool: True if the password contains the username, False otherwise.
        """
        
        if self.username and self.username in self.password:
            self.reason = "Password contains username"
            return True
        return False
    
    def __passwordsPWNED(self) -> bool:
        """
        Checks if the password has been pwned using the Have I Been Pwned API.
        This method hashes the password using SHA-1, splits the hash into a prefix and suffix,
        and queries the Have I Been Pwned API to check if the password has been compromised.
        Returns:
            bool: True if the password has been pwned, False otherwise.
        Raises:
            KeyError: If the API key is not found or invalid.
            requests.exceptions.RequestException: If there is an issue with the API request.
            json.JSONDecodeError: If there is an issue decoding the JSON configuration file.
        """
        
        sha1_hash = hashlib.sha1(self.password.encode()).hexdigest().upper()
        prefix, suffix = sha1_hash[:5], sha1_hash[5:]
        url = f"{self.HIBP_API_URL}/{prefix}"
        
        try:
            # Load API key from the configuration file
            with open(self.CONFIG_FILE_NAME, "r") as file:
                api_key = json.load(file).get("HIBP_API_KEY")
            if not api_key:
                raise KeyError("API key not found or invalid.")

            # Query the Have I Been Pwned API
            response = requests.get(url, headers={self.HIBP_HEADER: api_key})
            response.raise_for_status()
            
            for line in response.text.splitlines():
                hash_suffix, count = line.split(":")
                if hash_suffix == suffix:
                    self.reason = f"Password has been pwned {count} times"
                    return True
            return False
        except (requests.exceptions.RequestException, json.JSONDecodeError, KeyError) as e:
            print(f"Error: {e}")
            return False

    def __hasHighEntropy(self, threshold: float) -> bool:
        """
        Check if the password has high entropy.
        This method calculates the entropy of the password based on the 
        Shannon entropy formula. It determines if the entropy exceeds 
        a given threshold.
        Args:
            threshold (float): The entropy threshold to compare against. 
            
        Returns:
            bool: True if the password entropy is higher than the threshold, 
                False otherwise. If False, sets the reason attribute with 
                an explanation.
        """
        
        unique_chars = set(self.password)
        entropy = 0.0
        for char in unique_chars:
            Px = self.password.count(char) / len(self.password)
            entropy -= Px * math.log2(Px)
        
        if entropy > threshold:
            return True
        else:
            self.reason = f"Password entropy is too low: {entropy:.2f} (threshold: {threshold})"
            return False
        
    
    def __isSequential(self, max_sequence: int) -> bool:
        """
        Check if the password contains sequential characters.

        This method checks if the password contains a sequence of characters
        that are either incrementing or decrementing by 1. The length of the
        sequence to check for is determined by the `max_sequence` parameter.

        Args:
            max_sequence (int): The length of the sequence to check for.

        Returns:
            bool: True if the password contains a sequential sequence of characters, False otherwise.
        """
        
        password_values = [ord(c) for c in self.password]
        for i in range(len(password_values) - max_sequence + 1):
            sequence = password_values[i:i + max_sequence]
            if sequence == list(range(sequence[0], sequence[0] + max_sequence)) or \
                sequence == list(range(sequence[0], sequence[0] - max_sequence, -1)):
                self.reason = f"Password contains sequential characters: {''.join(map(chr, sequence))}"
                return True
        return False
    
    # [END] Private Helper methods
    
    # [START] Private Leveling methods
    
    def __level1(self) -> bool:
        """
        Checks if the password meets the criteria for level 1 security.

        The criteria for level 1 security are:
        - The password length must be greater than or equal to MIN_LENGTH_LEVEL_1.

        If the password meets this criterion, the method increments the point counter and returns True.
        Otherwise, it returns False.

        Returns:
            bool: True if the password meets level 1 security criteria, False otherwise.
        """
        
        if len(self.password) >= self.PASSWORD_MIN_LENGTH_LEVEL_1:
            self.__incrementPoint()
            return True
        return False
    
    def __level2(self) -> bool:
        """
        Checks if the password meets the criteria for level 2 security.

        The criteria for level 2 security are:
        - The password length must be greater than or equal to MIN_LENGTH_LEVEL_2.
        - The password must match at least REGEX_PATTERN_REQUIREMENT_LEVEL_2 patterns from REGEXES_PATTERNS.

        If the password meets these criteria, the method increments the point counter and returns True.
        Otherwise, it sets the reason attribute to indicate the failure and returns False.

        Returns:
            bool: True if the password meets level 2 security criteria, False otherwise.
        """
        
        if len(self.password) >= self.PASSWORD_MIN_LENGTH_LEVEL_2 and sum(bool(re.search(pattern, self.password)) for pattern in self.REGEXES_PATTERNS) >= self.REGEX_PATTERN_REQUIREMENT_LEVEL_2:
            self.__incrementPoint()
            return True
        self.reason = "Password is too short or does not contain enough character types (uppercase, lowercase, digits, special characters)"        
        return False
    
    def __level3(self) -> bool:
        """
        Checks if the password meets the criteria for level 3 security.
        The criteria for level 3 security are:
        - The password length must be greater than or equal to MIN_LENGTH_LEVEL_3.
        - The password must match at least REGEX_PATTERN_REQUIREMENT_LEVEL_3 patterns from REGEXES_PATTERNS.
        If the password meets these criteria, the method increments the security points and returns True.
        Otherwise, it sets the reason for failure and returns False.
        Returns:
            bool: True if the password meets level 3 security criteria, False otherwise.
        """
        
        if len(self.password) >= self.PASSWORD_MIN_LENGTH_LEVEL_3 and sum(
            bool(re.search(pattern, self.password)) for pattern in self.REGEXES_PATTERNS
        ) >= self.REGEX_PATTERN_REQUIREMENT_LEVEL_3:
            self.__incrementPoint()
            return True
        
        self.reason = "Password is too short or does not contain enough character types (uppercase, lowercase, digits, special characters)"
        return False
    
    def __level4(self) -> bool:
        """
        Checks if the password meets the criteria for level 4 security.
        Level 4 security criteria:
        - Password length must be greater than or equal to MIN_LENGTH_LEVEL_4.
        - Password must contain at least one uppercase letter, one lowercase letter, one digit, and one special character.
        - Password must not be found in the PWNED passwords database.
        - Password must not be a palindrome.
        - Password must not contain repetitive characters exceeding the REPETITIVE_CHAR_THRESHOLD_LEVEL_4.
        - Password must not contain sequential characters exceeding the SEQUENTIAL_CHAR_THRESHOLD_LEVEL_4.
        Returns:
            bool: True if the password meets all level 4 criteria, False otherwise.
        """
        
        if not len(self.password) >= self.PASSWORD_MIN_LENGTH_LEVEL_4:
            self.reason = "Password is short or does not contain enough character types (uppercase, lowercase, digits, special characters)"
            return False
        if (
            all(re.search(pattern, self.password) for pattern in self.REGEXES_PATTERNS) and
            not any([
            self.__passwordsPWNED(),
            self.__isPalindrome(),
            self.__isRepetitive(self.REPETITIVE_CHAR_THRESHOLD_LEVEL_4),
            self.__isSequential(self.SEQUENTIAL_CHAR_THRESHOLD_LEVEL_4)
            ])
        ):
            self.__incrementPoint()
            return True
        
        return False
    
    # [END] Private Leveling methods
    
    # [START] Public methods
    
    # [END] Public methods
    
def main():
    parser = argparse.ArgumentParser(description="PassChecker: Password Evaluation Tool")
    parser.add_argument("-p", "--password", type=str, help="[Required] Password to evaluate", required=True)
    parser.add_argument("-u", "--username", type=str, help="[Optional] Username to evaluate", required=False)

    args = parser.parse_args()
    
    tool = PassChecker(args.password, args.username)