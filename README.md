# File Protection Utility

A Python command-line utility that transforms file contents into a protected text format using a passphrase-derived key stream and restores the original file when verified.

## Features
- **Protect & Restore Modes:** Converts input files into a `.prot` protected format and restores them back to their original contents.
- **Passphrase Verification:** Uses a SHA-256 key stream and passphrase verification check to detect wrong passphrases or altered data.
- **Safe Text Encoding:** Encodes protected output cleanly in Base64 so it can be stored or moved easily.

## How to Run
1. Ensure Python 3 is installed on your system.
2. Run the script in your terminal:
   ```bash
   python file_protector.py
