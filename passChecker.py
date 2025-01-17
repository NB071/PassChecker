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
        
    # [END] Private Helper methods
    
    # [START] Private Leveling methods
    
    # [END] Private Leveling methods
    
    # [START] Public methods
    
    # [END] Public methods
    
def main():
    parser = argparse.ArgumentParser(description="PassChecker: Password Evaluation Tool")
    parser.add_argument("-p", "--password", type=str, help="[Required] Password to evaluate", required=True)
    parser.add_argument("-u", "--username", type=str, help="[Optional] Username to evaluate", required=False)

    args = parser.parse_args()
    
    tool = PassChecker(args.password, args.username)