# PassChecker: Advanced Password Evaluation Tool

<div align="center">
   <img src="https://i.ibb.co/593fXMP/Pass-1.png" width="450" height="450" />

</div>

## Overview
**PassChecker** is a Python-based tool designed to evaluate the strength of a password and identify potential weaknesses. The tool incorporates multiple levels of password strength evaluation, including length checks, character diversity, entropy analysis, detection of repetitive or sequential patterns, and integration with the "Have I Been Pwned" (HIBP) API for breach detection.

---

## Features
### 1. **Password Strength Evaluation**
   - Passwords are evaluated across 5 levels of strength:
     - **Level 0 (Hidden):** Reserved for invalid or extremely weak passwords (e.g., empty passwords).
     - **Level 1:** Minimum length requirement.
     - **Level 2:** Inclusion of at least two character types (uppercase, lowercase, digits, special characters).
     - **Level 3:** Inclusion of at least three character types.
     - **Level 4:** Advanced criteria including no repetition, no sequential patterns, and no breaches.
     - **Level 5:** High entropy, no inclusion of username, and no weak patterns.

### 2. **Entropy Calculation**
   - Uses the **Shannon entropy formula** to determine password randomness and complexity:

<div align="center">
    <img src="https://github.com/user-attachments/assets/2420a680-d7d1-4f45-9630-eaa2f2d20b51" alt="Entropy Formula" width=250 heigh=250 />
</div>
     Where:
     - \( H \): Entropy
     - \( P(x) \): Probability of the \( i \)-th character in the password
     - \( n \): Number of unique characters in the password

   - The formula calculates the unpredictability of the password based on the distribution of its characters. Higher entropy values indicate stronger passwords.
### 3. **Pattern Detection**
   - Detects repetitive characters and substrings.
   - Identifies sequential patterns (e.g., `12345`, `abcde`, `54321`).

### 4. **Palindrome Check**
   - Determines if the password is a palindrome (reads the same backward and forward).

### 5. **Username Validation**
   - Ensures the password does not include the username, if provided.

### 6. **Integration with HIBP API**
   - Checks if the password has been breached using the **Have I Been Pwned** API.

### 7. **Configurable Thresholds**
   - Adjustable criteria for entropy, repetition, and sequence detection thresholds.

### 8. **Command-Line Interface (CLI)**
   - Supports CLI usage with arguments for password and optional username.

---

## Installation
1. Clone this repository:
   ```bash
   git clone github.com/NB071/PassChecker/
   cd PassChecker
   ```
2. Install dependencies:
   ```bash
   pip install requests
   ```

---

## Usage

### Command-Line Interface
Run the tool using the following command:

```bash
python pass_checker.py -p <password> [-u <username>]
```

### Arguments
* `-p` or `--password` (Required): The password to evaluate.
* `-u` or `--username` (Optional): The username to check for inclusion in the password.

#### Example 
```bash
python passChecker.py -p MyP@ssP@ssP@ssword123 -u myusername
```

#### Output
The tool provides an assessment of the password strength, including:

* Password: The input password.
* Username: The provided username (if any).
* Level: The achieved password strength level.
* Title: A descriptive strength title.
* Reason: The reason for the assigned level (if any).

```bash
Password: 
Username: N/A
Level: 3 / 5
Title: Medium
Reason: Password has been pwned 262 times
```

--- 

## Configuration
The tool uses a `config.json` file to store the HIBP API key: 

```json
{
    "HIBP_API_KEY": "your-api-key-here"
}
```
rename `config-sample.json` to `config.json` in the root directory of the project.

---

## Dependencies
* Python 3.7+
* Libraries:
  * re (Regular expressions for pattern matching)
  * requests (For API calls)
  * json (To manage configurations)
  * math (For entropy calculations)
  * argparse (For CLI argument parsing)

--- 
## Strength Levels in Detail
Password strength is evaluated across 6 levels, from Level 0 (invalid passwords) to Level 5 (very strong passwords). Each level builds upon the criteria of the previous level, adding additional complexity and security requirements.

**Level 0: _Extremely Weak_**
* Criteria:
  * Password is empty or does not meet the minimum requirements for Level 1.
* Example:
  * `""` (empty string)
  * `abc` (too short, lacks complexity)
* **Result**: The password is rejected outright as invalid.

---

**Level 1: _Very Weak_**
* **Criteria**:
  * Password must be at least **6 characters** long.
* **Example**:
  * `pass12`
  * `1234abc`
* **Reason for Weakness**:
  * The password still lacks sufficient diversity or length to resist targeted attacks.

---

**Level 2: _Weak_** 
* **Criteria**:
  * Password must be at least **8 characters** long.
  * Password must include **at least 2 character types**:
    * Uppercase letters (A-Z)
    * Lowercase letters (a-z)
    * Digits (0-9)
    * Special characters .
* **Example**:
  * `p@ssw0rD`
  * `eSp3cT@rr`
* **Reason for Weakness**:
  * While stronger than Level 1, these passwords may still rely on predictable patterns.

 ---
 
**Level 3: _Medium_**  
* **Criteria**:
  * Password must be at least **10 characters** long.
  * Password must include **3 character types** (uppercase, lowercase, digits, special characters)
* **Example**:
  * `Pass@word12`
  * `M3diumLevel`
* **Reason for Medium Strength**:
  * The password meets a reasonable standard of complexity and length.

---

**Level 4: _Strong_**  
* **Criteria**:
  * Password must be at least **12 characters** long.
  * Password must include **all 4 character types**.
  * Password must **not**:
    * Contain repetitive characters (_max=4_):
      * **Joined Repetitive Characters**: These are patterns where the same character or group of characters appears consecutively without breaks, example:
        * `aaaaaaa` (single character repeated)
        * `abababab` (repeated substring of ab)
        * `11112222` (repeated digit groups)
      * **Sparse Repetitive Characters**: These are patterns where the same character or group of characters repeats multiple times within the password but with gaps in between, example:
        * `a1a2a3a4` (repetition of a with sparse digits in between)
        * `xy12xy34xy` (repeated xy with sparse numbers)
        * `P@ssP@ss12` (repetition of the word P@ss)
    * Contain **more than 4** sequential characters (e.g., `1234`, `abcd`).
    * Be found in the "Have I Been Pwned" database.
* **Example**:
  * `Str0ng@Paswd`
  * `R3al$ecur3P@ss`
* **Reason for Strength**:
  * The password meets high standards for length and complexity.
  * It resists common brute force, dictionary, and pattern-based attacks.

---

**Level 5: _Very Strong_**  
* **Criteria**:
  * Password must be at least **14 characters** long.
  * all criteria of level 5
  * Password must **not**:
    * Contain repetitive characters (_max=3_, less than level 4).
    * Contain sequential characters (_max=3_, less than level 4).
    * Be a palindrome.
    * Include the username (if provided).
  * Password must have **high entropy** (above 3.55 bits per character).
* **Example**:
  * `My$uperStr0ngP@ss103`
  * `Th!s1sAV3rySecur3K3y`
* **Reason for Very Strong Strength**:
  * These passwords are highly resistant to brute force, dictionary, and targeted attacks.
  * They exhibit a high degree of randomness and length.

---

## Future Enhancements
  1. **Custom Policies**: Allow users to define custom password strength requirements (e.g., specific length, character types, or entropy thresholds).
  2. **Integration with Other APIs**: Add more security databases for password breach checks.
  3. **Graphical User Interface (GUI)**: Create a user-friendly desktop or web-based GUI for easier interaction.
  4. **Batch Mode**: Allow evaluation of multiple passwords from a file.
  5. **Command-line Switches**: implement more robust and comprehensive DX by creating more switches for the program, eg. -v for verbose output.

---

## Acknowledgments
The development of PassChecker was inspired by several key frameworks and resources that emphasize password security and best practices:
  * **NIST Special Publication 800-63B**
  * **Have I Been Pwned (HIBP)**
  * **OWASP Password Storage Cheat Sheet**
