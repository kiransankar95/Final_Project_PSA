# Final_Project_PSA

# 🔐 Password Strength Analyzer with Custom Wordlist Generator

## 📘 Project Overview
This project provides a dual-function cybersecurity tool that performs:

1. *Password Strength Analysis*
2. *Custom Wordlist Generation*

The tool analyzes password robustness using entropy calculations and optional zxcvbn scoring. It also generates targeted wordlists based on user-provided hints, useful for security testing and ethical hacking practice.

---

## 🎯 Objectives
- Evaluate password strength using entropy and pattern checks.
- Allow users to input personal hints (names, dates, keywords).
- Produce custom wordlists with:
  - Leetspeak variations  
  - Capitalized versions  
  - Appended/prepended years  
  - Common suffixes
- Export the final wordlist as .txt.

---

## 🛠 Tools & Technologies Used
- *Python*
- argparse
- itertools
- re
- zxcvbn-python (optional)
- tkinter (optional GUI)

---

## 📂 Features Overview

### *1. Password Strength Analyzer*
- Entropy calculation  
- Detection of character types (uppercase, digits, symbols)  
- Optional detailed analysis with zxcvbn  

### *2. Custom Wordlist Generator*
- Takes multiple user hints  
- Generates permutations and variations  
- Adds suffixes and year patterns  
- Produces leetspeak alternatives  
- Saves output as .txt  

---

## 🧑‍💻 Usage Summary

### CLI Example:
```bash
python psa_wordlist.py --analyze "P@ssw0rd!" --hints "word,2024,pets" --years 1990 2025 --out wordlist.txt
```

📌CONCLUSION

This project provides a practical cybersecurity tool combining password strength analysis with a flexible wordlist generator. It demonstrates skills in Python programming, security concepts, and tool-building—making it valuable for learning, interviews, and real-world cybersecurity tasks.
