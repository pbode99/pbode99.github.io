---
title: "Writeup 1: Cryptography Foundations: ECB Leakage, XOR, and a Redaction Lesson"
date: 2026-09-24 22:00:00 -0400
categories: [Writeups, Cryptography]
tags: [cryptohack, aes, ecb, cbc, xor, padding-oracle, overthewire, lab-setup]
image:
  path: /assets/img/writeup-1/ecb-vs-cbc.png
  alt: The same image as plaintext, encrypted with AES-ECB, and encrypted with AES-CBC
---

> **Module A1: Cryptography & PKI** · CS 419 Computer Security, Fall 2026 · Honors CTF Track
>
> This is the first of five writeups. Each one pairs an **attacker walkthrough** (how the weakness was found and exploited) with a **defender's analysis** (root cause, CWE, correct fix, and how to detect it). No live flags or credentials appear here. Flags are redacted, and only challenges that CryptoHack allows to be published (Starter challenges and those worth 25 points or less) are discussed in detail.
{: .prompt-info }

## 1. Problem summary and threat context

Most real cryptographic failures don't come from someone breaking AES. They come from using a sound primitive the wrong way: the wrong **mode of operation**, a key that is far too small, or ciphertext that tells the attacker something through its structure or its error messages. This module looks at that gap between a strong cipher and a secure system, through three small experiments:

1. **ECB pattern leakage.** Encrypting an image with AES and still being able to read it.
2. **Single-byte XOR.** A "cipher" whose entire keyspace fits in a `for` loop.
3. **The padding oracle.** Why switching from ECB to CBC isn't enough on its own. I analyzed this attack rather than implementing it (see §4.2).

I also include a short account of the Week 1 lab setup, because every later module runs in this environment. It turned up a small defender's lesson of its own.

## 2. The lab environment (Week 1)

All work runs in an isolated **Kali Linux VM on VirtualBox**, with a clean-baseline snapshot taken before any challenge work so the machine can be rolled back at any point.

![Kali Linux desktop in VirtualBox with Ghidra, Burp Suite, Wireshark and a terminal](/assets/img/writeup-1/lab-desktop.png)
_The lab VM: Ghidra, Burp Suite and Wireshark come preinstalled with Kali; pwndbg was added from its GitHub repository._

![gdb starting with the pwndbg extension loaded](/assets/img/writeup-1/pwndbg.png)
_gdb with pwndbg loaded, confirming the debugger toolchain for the memory-corruption module later this term._

To warm up on the command line I worked through the early levels of **OverTheWire Bandit**. Two of them turned out to be relevant to security and not just CLI practice. Passwords are redacted, since OverTheWire permits walkthroughs but not published credentials.

![Bandit level 2: cat fails on a filename with spaces and leading dashes until prefixed with ./ and quoted](/assets/img/writeup-1/bandit-level2.png)
_Level 2: the filename `--spaces in this filename--` gets split on spaces and parsed as an option. Quoting it and prefixing `./` fixes both problems._

![Bandit level 4: files named -file00 through -file09 read with a ./ prefix; output redacted](/assets/img/writeup-1/bandit-level4.png)
_Level 4: files named `-file00` … `-file09` are read as flags by `du`, `file` and `cat` until they're written as paths (`./-file07`)._

**Defender's note: argument injection (CWE-88).** In both levels, *data* (a filename) gets interpreted as *control* (a command-line option), because the program can't tell where options end and operands begin. Here that's a puzzle. In a real script it's a vulnerability: a web app that runs `tar` or `rsync` on user-supplied filenames can be handed a file named `--checkpoint-action=exec=...` and end up running attacker-chosen commands. The fixes are the same ones that solved the levels. Pass `--` to mark the end of options, pass file paths as `./name` rather than `name`, and never build command strings from untrusted input. This is also a preview of the command-injection module in Week 8.

## 3. Attacker walkthrough

### 3.1 ECB pattern leakage

**Setup.** I wrote a short Python script (pycryptodome + Pillow) that takes the raw RGB pixels of an image, encrypts them with AES-128 twice, once in **ECB** and once in **CBC**, using the *same random key*, and writes each ciphertext back into an image of the same dimensions. The header is kept in the clear so the result still displays. Only the pixel bytes are encrypted.

```python
key = os.urandom(16)                        # ONE key for both runs
data = img.tobytes()                        # raw pixels only

ecb = AES.new(key, AES.MODE_ECB).encrypt(pad(data, 16))
cbc = AES.new(key, AES.MODE_CBC, iv=os.urandom(16)).encrypt(pad(data, 16))

def repeat_stats(ct):                       # how many 16-byte blocks repeat?
    blocks = [ct[i:i+16] for i in range(0, len(ct), 16)]
    return len(blocks), len(set(blocks))
```

The test image is deliberately simple: flat colors, solid shapes and block text. Those are exactly the conditions under which many 16-byte plaintext blocks are identical.

**Result.**

![Terminal output showing 97.6% repeated blocks under ECB and 0.0% under CBC, with the ECB image open alongside](/assets/img/writeup-1/ecb-terminal.png)
_Running the demo in the VM. The earlier errors in the scrollback are real, from a missing file path on the first attempts._

| Mode | Ciphertext blocks | Unique blocks | Repeated |
|------|------------------:|--------------:|---------:|
| AES-ECB | 45,001 | 1,076 | **97.6%** |
| AES-CBC | 45,001 | 45,001 | **0.0%** |

The image is 600 × 400 × 3 bytes = 720,000 bytes, which is 45,000 blocks plus one block of padding. Under ECB, only 1,076 of those blocks are distinct.

![Plaintext image, its AES-ECB encryption with shapes and text still visible, and its AES-CBC encryption as uniform noise](/assets/img/writeup-1/ecb-vs-cbc.png)
_Left to right: plaintext, AES-ECB, AES-CBC. Same key, same cipher, same input. Only the mode differs. "CS 419 HONORS" is still readable through AES._

**Why it works.** ECB encrypts each 16-byte block independently: `C_i = E_K(P_i)`. AES is a deterministic permutation under a fixed key, so identical plaintext blocks *always* produce identical ciphertext blocks. Every run of white background maps to one ciphertext value and every run of red maps to another. The colors change, but where the edges are, and so the picture, survives. CBC chains the blocks, `C_i = E_K(P_i ⊕ C_{i-1})` with a random IV as `C_0`, so the same plaintext block encrypts differently depending on everything before it. Encrypting the same image twice gives completely different output.

A useful control is to run the demo again. The second ECB image uses a new random key and different colors, and it shows the same shapes. **The leak does not depend on the key**, so no amount of key rotation fixes it.

### 3.2 Single-byte XOR (CryptoHack: Introduction → Great Snakes)

This challenge gives you a Python script containing a list of integers and a one-line decoder:

![VS Code showing the Great Snakes script with the ordinal list and the flag output both redacted](/assets/img/writeup-1/great-snakes.png)
_Both the ciphertext array (line 9) and the output are redacted. See §4.4 for why redacting only the output wasn't enough._

The decoder is `chr(o ^ 0x32)` applied to each value. That is XOR with a **single-byte key** (`0x32`). XOR is its own inverse (`(p ⊕ k) ⊕ k = p`), so the same operation encrypts and decrypts. With a one-byte key the entire keyspace is **256 values**. Even without being given `0x32`, an attacker tries every byte and keeps the output that starts with the known flag prefix `crypto{`. That known-plaintext shortcut is exactly what the next challenges in the set (Favourite byte, XOR Properties) formalize.

## 4. Defender's analysis

### 4.1 ECB mode

| | |
|---|---|
| **Root cause** | A deterministic mode: equal plaintext blocks become equal ciphertext blocks, so the ciphertext reveals which blocks are equal to each other. |
| **CWE** | [CWE-327](https://cwe.mitre.org/data/definitions/327.html): Use of a Broken or Risky Cryptographic Algorithm (ECB mode specifically). |
| **Correct fix** | Use an **authenticated** mode such as AES-GCM or ChaCha20-Poly1305, with a unique nonce per message. Don't just switch to CBC (see §4.2). Better still, use a high-level library (libsodium, Tink, `cryptography`'s Fernet/AESGCM) that doesn't expose a mode choice at all. |
| **Detection** | *Statically:* flag `MODE_ECB`, `AES/ECB/…`, or Java's default `Cipher.getInstance("AES")` (which silently means ECB). Static analyzers such as Semgrep and the Python linter Bandit (not to be confused with the wargame) ship rules for this. *Dynamically:* the `repeat_stats` function above is itself a detector. Any ciphertext with repeated aligned 16-byte blocks is almost certainly ECB. |

Images make the leak visible, but the real damage is to **structured data**: database columns with repeated values, fixed-format tokens and session cookies. In those, ECB reveals equality ("these two users have the same password hash") and, as CryptoHack's *ECB Oracle* challenge shows, can be turned into byte-at-a-time plaintext recovery. The leak scales with redundancy. High-entropy data such as photographs *looks* fine under ECB, and that makes it more dangerous, because it hides the problem.

### 4.2 Why CBC is not the answer: the padding oracle (analyzed, not implemented)

CBC fixes the *pattern* leak but provides **no integrity**, and that opens a different attack. In CBC decryption, `P_i = D_K(C_i) ⊕ C_{i-1}`. An attacker who can change `C_{i-1}` controls the XOR mask on the decrypted `P_i` byte for byte. If the server responds differently to *bad padding* than to *bad data* (a different error message, status code, or even response time), it becomes an **oracle**. The attacker changes the last byte of `C_{i-1}` until the padding is accepted, which reveals the last byte of `D_K(C_i)`, and so the plaintext byte. Then the process repeats for each remaining byte. That's at most 256 guesses per byte, with no key required.

This isn't hypothetical. It broke ASP.NET in 2010 (Rizzo & Duong), and variants of it, such as Lucky Thirteen (2013) and POODLE (2014), forced changes in TLS.

| | |
|---|---|
| **Root cause** | Unauthenticated ciphertext is decrypted and parsed, and the result of that parsing is observable. |
| **CWE** | [CWE-209](https://cwe.mitre.org/data/definitions/209.html): Information Exposure Through an Error Message, combined with [CWE-353](https://cwe.mitre.org/data/definitions/353.html): Missing Support for Integrity Check. |
| **Correct fix** | Authenticate before decrypting (encrypt-then-MAC), or use an AEAD mode (AES-GCM), which rejects tampered ciphertext before any padding is examined. Return one uniform error for every decryption failure. |
| **Detection** | Look for large numbers of near-identical requests that differ only in one ciphertext block, and a spike in decryption failures from a single client. Rate-limit and alert on both. |

For scope reasons this week I analyzed the attack rather than implementing it. An implementation is a candidate for the revised version of this writeup.

### 4.3 Single-byte XOR

**Root cause:** a key that's far too small, used like a one-time pad. It maps to [CWE-326](https://cwe.mitre.org/data/definitions/326.html) (Inadequate Encryption Strength) and CWE-327. **Fix:** don't write your own cipher. Use a vetted AEAD with a 128-bit or 256-bit key. **Detection:** XOR-with-a-short-key is a favorite of malware authors for obfuscating strings, which is why triage tools such as `xorsearch` and CyberChef's XOR brute force exist. I'll come back to this in the Week 9 malware triage.

### 4.4 A finding from my own screenshot: incomplete redaction (CWE-212)

My first screenshot of Great Snakes had a colored box over the flag in the terminal. But line 9 of the script, the list of ciphertext integers, was still visible in the same image, and `chr(o ^ 0x32)` was right below it. Anyone reading the post could have recovered the flag in a single line of Python. **The redaction hid the output but left the input.**

That's [CWE-212](https://cwe.mitre.org/data/definitions/212.html): Improper Removal of Sensitive Information Before Storage or Transfer. It's the same failure as the court filings and government PDFs where a black box is drawn over text that is still in the document's text layer. The defender's rule is to redact **everything from which the secret can be derived**, not only the secret itself, and to check the redacted artifact by trying to recover the secret from it. Every screenshot in this post was checked that way.

## 5. Reflection and connection to lecture

Symmetric encryption in practice is a primitive *plus a mode of operation*, and this week showed why the mode deserves as much attention as the cipher. Three lessons carry forward:

- **Confidentiality isn't only about secrecy of content.** Leaking *equality*, *structure* or *error behavior* is enough to break a system. ECB leaks structure, and a padding oracle leaks one bit per query, which is enough.
- **Confidentiality without integrity isn't secure.** That's why modern designs default to AEAD, and it leads directly into this module's second half: hashes, MACs and signatures.
- **Small keyspaces fall to brute force regardless of the algorithm.** The same arithmetic will matter for RSA parameter choices in the next set.

**Tooling used:** Python 3 (pycryptodome, Pillow) in a venv on Kali, VS Code, gdb/pwndbg, and the CryptoHack and OverTheWire platforms. One practical note from setup: Kali (Python 3.14) blocks system-wide `pip install` under PEP 668, so all tooling lives in a virtual environment at `~/ctf/venv`, which also keeps the VM reproducible.

## 6. Progress and next steps

- **Completed:** lab VM and toolchain setup with baseline snapshot; OverTheWire Bandit warm-up; ECB vs. CBC leakage demonstration; CryptoHack *Great Snakes*.
- **Analyzed, not implemented:** CBC padding-oracle decryption.
- **In progress for the revised writeup:** the rest of CryptoHack's General (Encoding, XOR) and AES-structure sets, the RSA / public-key and Hashes sets, and the Week 3 weak-RSA and hash/signature-flaw exploits.

The contract anticipates iterating on each writeup after faculty feedback, and this one will be revised as the remaining module A1 challenges are completed.
