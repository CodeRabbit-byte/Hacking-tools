# 🛠 Hacking Tools Collection

A single-file Python toolkit for **CTF players, pentesting students, and security hobbyists**.
It combines utilities for:

- Encoding/decoding
- Crypto attacks and helpers
- Reverse engineering triage
- Web testing payload helpers
- Forensics helpers
- OSINT helpers
- Networking quick checks
- General CTF utilities

Main script: `hacking.py`

---

## 📦 Installation

```bash
git clone https://github.com/CodeRabbit-byte/Hacking-tools.git
cd Hacking-tools
python3 -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install pycryptodome gmpy2 requests owiener pyperclip
```

> The tool still runs without optional packages, but some features will be limited.

---

## 🚀 Quick Start

### 1) Launch interactive mode

```bash
python3 hacking.py
```

This opens the main menu where you can navigate by entering the numbered options.

### 2) Decode a string directly from CLI

```bash
python3 hacking.py --magic "ZmxhZ3t0b29sa2l0fQ=="
```

### 3) Auto-triage a file from CLI

```bash
python3 hacking.py --auto ./sample.bin
```

---

## 🧭 Elaborate Usage Guide

## 1. Encoding / Magic Decoder

### Best for
- Unknown encoded strings
- CTF flags hidden through layered encoding

### Workflow
1. Choose `Encoding / Magic Decoder` from main menu.
2. Paste your input.
3. Review all decode attempts (Base64, Base32, Base85, hex, binary, ROT13, Caesar, decimal ASCII, morse, URL, HTML).
4. If a flag-like pattern is found, it is highlighted automatically.

### Tip
If a result looks partially readable, feed that output back into magic decode again.

---

## 2. Cryptography Attacks

### Included
- RSA small exponent
- RSA common modulus
- RSA Wiener attack
- RSA Fermat factorization
- Manual RSA decrypt
- Vigenère crack
- XOR crack
- Hash identify + wordlist brute-force
- AES-ECB pattern analysis
- Padding-oracle concept demo

### Typical RSA solve path
1. Try **Small exponent** first when `e=3` and plaintext was unpadded.
2. If same `n` appears with two exponents, try **Common modulus**.
3. If `d` suspected small, try **Wiener**.
4. If `p≈q`, try **Fermat**.
5. Fall back to **Manual decrypt** when parameters are known.

### Example: hash brute force
```bash
python3 hacking.py
# Crypto -> Hash brute force
# Enter target hash + wordlist + algo
```

---

## 3. Reverse Engineering Toolkit

### Included
- Full recon sweep
- String extraction with regex filters
- Function disassembly wrapper
- Binary byte patching
- Anti-debug pattern checks
- ELF header parser
- RE checklist

### Recommended workflow
1. Run full recon.
2. Extract strings and search `flag|key|pass|secret`.
3. Disassemble suspicious functions (`main`, `check_flag`, etc.).
4. Patch conditional jumps if needed.
5. Re-run and compare behavior.

---

## 4. Web Security Toolkit

### Included
- SQLi probes (error/boolean/time style checks)
- XSS payload bank
- LFI helper
- JWT helper actions
- Directory brute helper
- SSRF payload generator
- Parameter fuzzer
- Raw HTTP requester

### Practical usage
- Use it as a **payload + workflow assistant**, not a scanner replacement.
- Keep legal scope boundaries strict (CTF/labs/authorized targets only).

---

## 5. Forensics Toolkit

### Included
- File-type and metadata checks
- Steganography helper commands
- PCAP analysis helper
- File carving helper
- Hex viewer
- PNG LSB extractor
- Entropy calculator

### Workflow
1. Start with file analysis and entropy.
2. Pull metadata.
3. Try strings/hex/LSB.
4. Carve with `binwalk` if suspicious archive data exists.

---

## 6. OSINT Toolkit

### Included
- Domain/IP recon helper
- Email header analyzer
- Image metadata guidance
- Username search guidance
- Geolocation helper
- Google dork builder

### Note
Some modules provide command/query templates so you can execute quickly with your preferred tools.

---

## 7. Networking Toolkit

### Included
- Port scanner
- Banner grabber
- Netcat helper
- Nmap wrapper
- Protocol/hex decode helper

### Suggested order
1. Basic port scan.
2. Banner grab on live ports.
3. Deepen with nmap scripts and service versioning.

---

## 8. Utilities

### Included
- Number base conversion
- String/byte/int conversion
- Flag finder regex helper
- URL encode/decode
- Random payload generator
- Flag format validator
- ROT brute
- Frequency analysis
- One-liner cheatsheet

### Good use cases
- Quickly validate candidate flags.
- Convert challenge values across decimal/hex/binary.
- Generate test payloads for local exploit prototyping.

---

## 🧪 Running the test suite

A local automated unit test suite is included.

```bash
python3 -m unittest -v tests/test_hacking.py
python3 -m py_compile hacking.py tests/test_hacking.py
```

The tests cover key deterministic behavior such as decoding helpers, conversion tools, hash identification flow, command execution wrapper behavior, and auto-triage text handling.

---

## ⚠️ Important Notes

- This project is intended for **CTFs, labs, and authorized security testing only**.
- Some modules call external binaries (`strings`, `objdump`, `readelf`, `nmap`, etc.). Install those tools for full functionality.
- Optional Python dependencies are auto-detected at runtime.

---

## ⭐ Purpose

Reduce repetitive CTF workflow friction so you can focus on analysis and solving.
