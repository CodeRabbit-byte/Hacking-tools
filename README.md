# 🛠 Hacking Tools Collection

A compact toolkit built for **CTF players, security researchers, and reverse engineers**.  
It combines utilities for **decoding, cryptography attacks, reverse engineering, web security testing, forensics, OSINT, and networking**.

---

## 📦 Installation

Clone the repository:

```bash
git clone https://github.com/yourusername/hacking-tools.git
cd hacking-tools
```

Install required dependencies:

```bash
pip install pycryptodome gmpy2 requests owiener pyperclip
```

---

## 📚 Table of Contents

- [Features](#features)
  - [Magic Decoder](#magic-decoder)
  - [Cryptography Tools](#cryptography-tools)
  - [Reverse Engineering Toolkit](#reverse-engineering-toolkit)
  - [Web Security Toolkit](#web-security-toolkit)
  - [Digital Forensics Tools](#digital-forensics-tools)
  - [OSINT Utilities](#osint-utilities)
  - [Networking Tools](#networking-tools)
  - [General Utilities](#general-utilities)

---

# 🔧 Features

## 🔓 Magic Decoder

Automatically attempts multiple decoding techniques to reveal hidden data.

### Supported Decoders

- Base64  
- Base32  
- Base85  
- Hex  
- Binary  
- ROT13  
- Caesar cipher (bruteforce)  
- Decimal ASCII  
- Morse code  
- HTML entities  
- URL decoding  

### Capabilities

- Automatically runs multiple decoding attempts  
- Detects potential flag patterns  
- Highlights discovered flags  

---

## 🔐 Cryptography Tools

Tools designed for analyzing and attacking common cryptographic schemes.

### RSA Attacks

- Small-e cube root attack  
- Common modulus attack  
- Wiener's attack  
- Fermat factorization  
- Manual RSA decryption helper  

### Classical & Modern Crypto

- Vigenère cipher cracker (IoC analysis)  
- XOR key recovery  
- Hash type identifier  
- Wordlist-based hash brute forcing  
- AES-ECB block detection  
- Padding oracle attack framework  

---

## 🔍 Reverse Engineering Toolkit

Utilities for analyzing binaries and identifying protections.

### Features

- Full binary reconnaissance sweep  
- String extraction  
- Disassembly using `objdump`  
- Byte patching (NOP-out jumps)  
- Anti-debug detection scanner  
- ELF header parser  
- Interactive reverse engineering checklist  

---

## 🌐 Web Security Toolkit

Tools for testing common web application vulnerabilities.

### Modules

**SQL Injection Tester**

- Error-based  
- Boolean-based  
- Time-based  

**Other Tools**

- XSS payload library  
- LFI fuzzer  
- JWT attack toolkit  
  - `alg=none` bypass  
  - HS256 brute force  
  - Payload modification  
- Directory brute forcer  
- SSRF payload generator  
- Parameter fuzzer  
- Raw HTTP request sender  

---

## 🔎 Digital Forensics Tools

Utilities for analyzing files and extracting hidden data.

### Features

- File analysis and entropy calculation  
- Steganography testing  
  - `stegseek`  
  - `steghide`  
  - `zsteg`  
- PCAP analysis using `tshark`  
- Metadata extraction  
- File carving with `binwalk`  
- Hex viewer  
- PNG LSB data extractor  

---

## 🌍 OSINT Utilities

Tools for gathering open-source intelligence.

### Capabilities

- Domain and IP reconnaissance  
- Email header analysis  
- Geolocation from EXIF metadata  
- Google dork generator  
- Username search across platforms  

---

## 📡 Networking Tools

Networking utilities for reconnaissance and protocol analysis.

### Functions

- Socket-based port scanner  
- Banner grabbing  
- `nmap` wrapper  
- Protocol hex decoder  

---

## 🛠 General Utilities

Helpful tools commonly used during CTFs and security workflows.

- Number base converter  
- ROT cipher brute force (all 25 variations)  
- Frequency analysis  
- URL encode / decode  
- Flag format validator  
- Cyclic payload generator  
- Python one-liner cheat sheet  

---

⭐ **Purpose**

This toolkit aims to streamline repetitive tasks during **CTFs, pentesting labs, and security research**, allowing faster analysis and problem solving.
