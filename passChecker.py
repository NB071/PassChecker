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
    
def main():
    parser = argparse.ArgumentParser(description="PassChecker: Password Evaluation Tool")
    parser.add_argument("-p", "--password", type=str, help="[Required] Password to evaluate", required=True)
    parser.add_argument("-u", "--username", type=str, help="[Optional] Username to evaluate", required=False)

    args = parser.parse_args()
    
    tool = PassChecker(args.password, args.username)