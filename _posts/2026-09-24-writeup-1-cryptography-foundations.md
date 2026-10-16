---
title: "Writeup 1: Cryptography Foundations: ECB Leakage, XOR, and a Redaction Lesson"
date: 2026-09-24 22:00:00 -0400
categories: [Writeups, Cryptography]
tags: [cryptohack, aes, ecb, cbc, xor, padding-oracle, overthewire, lab-setup]
image:
  path: /assets/img/writeup-1/ecb-vs-cbc.png
  alt: The same image as plaintext, encrypted with AES-ECB, and encrypted with AES-CBC
---

> This is the first of five writeups. Each one pairs an attacker walkthrough, meaning how I found and exploited the weakness, with a defender's analysis of the root cause, the CWE, the correct fix, and how to detect it. No live flags or credentials appear here. I redact flags, and I only discuss in detail the CryptoHack challenges that the platform allows me to publish, which are the Starter challenges and those worth 25 points or less.
{: .prompt-info }

## 1. Problem summary and threat context

Most real cryptographic failures do not come from someone breaking AES. They come from using a sound primitive the wrong way. The wrong mode of operation, a key that is far too small, or ciphertext that quietly tells the attacker something through its structure or its error messages. This module looks at the gap between a strong cipher and a secure system. I studied that gap through three small experiments: ECB pattern leakage, where I encrypt an image with AES and can still read it; single-byte XOR, a cipher whose entire keyspace fits in a for loop; and the padding oracle, which shows why switching from ECB to CBC is not enough on its own. I analyzed the padding oracle rather than implementing it, and I explain that choice in section 4.2.

I also include a short account of the Week 1 lab setup. Every later module runs in this environment, and the setup turned up a small defender's lesson of its own.

## 2. The lab environment (Week 1)

All of my work runs in an isolated Kali Linux VM on VirtualBox. I took a clean-baseline snapshot before any challenge work so I can roll the machine back at any point.

![Kali Linux desktop in VirtualBox with Ghidra, Burp Suite, Wireshark and a terminal](/assets/img/writeup-1/lab-desktop.png)
_The lab VM. Ghidra, Burp Suite and Wireshark come preinstalled with Kali. I added pwndbg from its GitHub repository._

![gdb starting with the pwndbg extension loaded](/assets/img/writeup-1/pwndbg.png)
_gdb with pwndbg loaded, confirming the debugger toolchain for the memory-corruption module later this term._

To warm up on the command line I worked through the early levels of OverTheWire Bandit. Two of them turned out to matter for security and not just for CLI practice. I redact the passwords, since OverTheWire permits walkthroughs but not published credentials.

![Bandit level 2: cat fails on a filename with spaces and leading dashes until prefixed with ./ and quoted](/assets/img/writeup-1/bandit-level2.png)
_Level 2. The filename with spaces gets split and parsed as options. Quoting it and prefixing ./ fixes both problems._

![Bandit level 4: files named -file00 through -file09 read with a ./ prefix; output redacted](/assets/img/writeup-1/bandit-level4.png)
_Level 4. Files named -file00 through -file09 are read as flags by du, file and cat until I write them as paths like ./-file07._

There is a defender's lesson buried in both levels, and it maps to CWE-88, argument injection. In each case data, meaning a filename, gets interpreted as control, meaning a command-line option, because the program cannot tell where options end and operands begin. Here that is a puzzle. In a real script it is a vulnerability. A web app that runs tar or rsync on user-supplied filenames can be handed a file named something like --checkpoint-action=exec=... and end up running commands the attacker chose. The fixes are the same ones that solved the levels. I pass -- to mark the end of options, I pass file paths as ./name rather than name, and I never build command strings out of untrusted input. This also previews the command-injection module in Week 8.

## 3. Attacker walkthrough

### 3.1 ECB pattern leakage

I wrote a short Python script using pycryptodome and Pillow. It takes the raw RGB pixels of an image and encrypts them with AES-128 twice, once in ECB and once in CBC, using the same random key. It then writes each ciphertext back into an image of the same dimensions. I keep the header in the clear so the result still displays, and I encrypt only the pixel bytes.

```python
key = os.urandom(16)                        # ONE key for both runs
data = img.tobytes()                        # raw pixels only

ecb = AES.new(key, AES.MODE_ECB).encrypt(pad(data, 16))
cbc = AES.new(key, AES.MODE_CBC, iv=os.urandom(16)).encrypt(pad(data, 16))

def repeat_stats(ct):                       # how many 16-byte blocks repeat?
    blocks = [ct[i:i+16] for i in range(0, len(ct), 16)]
    return len(blocks), len(set(blocks))
```

I chose a deliberately simple test image. Flat colors, solid shapes, and block text. Those are exactly the conditions under which many 16-byte plaintext blocks come out identical.

![Terminal output showing 97.6% repeated blocks under ECB and 0.0% under CBC, with the ECB image open alongside](/assets/img/writeup-1/ecb-terminal.png)
_Running the demo in the VM. The earlier errors in the scrollback are real, from a missing file path on the first attempts._

The numbers tell the story. The image is 600 by 400 by 3 bytes, which is 720,000 bytes, or 45,000 blocks plus one block of padding. Under ECB, the ciphertext has 45,001 blocks but only 1,076 of them are distinct, so 97.6 percent of the blocks are repeats. Under CBC, all 45,001 blocks are unique and nothing repeats.

![Plaintext image, its AES-ECB encryption with shapes and text still visible, and its AES-CBC encryption as uniform noise](/assets/img/writeup-1/ecb-vs-cbc.png)
_Left to right: plaintext, AES-ECB, AES-CBC. Same key, same cipher, same input. Only the mode differs. "CS 419 HONORS" is still readable through AES._

Here is why it works. ECB encrypts each 16-byte block on its own, so the ciphertext for block i is just the encryption of plaintext block i. AES is a deterministic permutation under a fixed key, so identical plaintext blocks always produce identical ciphertext blocks. Every run of white background maps to one ciphertext value, and every run of red maps to another. The colors change but the edges stay where they are, so the picture survives. CBC chains the blocks instead. It XORs each plaintext block with the previous ciphertext block before encrypting, and it starts from a random IV. The same plaintext block encrypts differently depending on everything before it, so encrypting the same image twice gives completely different output.

I ran a useful control. The second ECB image uses a new random key and different colors, and it shows the same shapes. The leak does not depend on the key, so no amount of key rotation fixes it.

### 3.2 Single-byte XOR (CryptoHack: Introduction, Great Snakes)

This challenge gives you a Python script with a list of integers and a one-line decoder.

![VS Code showing the Great Snakes script with the ordinal list and the flag output both redacted](/assets/img/writeup-1/great-snakes.png)
_Both the ciphertext array on line 9 and the output are redacted. Section 4.4 explains why redacting only the output was not enough._

The decoder applies chr(o ^ 0x32) to each value, which is XOR with a single-byte key of 0x32. XOR is its own inverse, so the same operation encrypts and decrypts. With a one-byte key the entire keyspace is 256 values. Even if I had not been given 0x32, I could try every byte and keep the output that starts with the known flag prefix crypto{. That known-plaintext shortcut is exactly what the later challenges in the set, Favourite byte and XOR Properties, formalize.

## 4. Defender's analysis

### 4.1 ECB mode

The root cause is a deterministic mode. Equal plaintext blocks become equal ciphertext blocks, so the ciphertext reveals which blocks are equal to each other. This is CWE-327, use of a broken or risky cryptographic algorithm, with ECB mode being the specific problem. The correct fix is to use an authenticated mode such as AES-GCM or ChaCha20-Poly1305, with a unique nonce per message. Do not just switch to CBC, for reasons I give in the next section. Better still, use a high-level library such as libsodium, Tink, or the Fernet and AESGCM helpers in the cryptography package, so no one has to choose a mode at all. Detecting this is practical from two directions. Statically, I can flag MODE_ECB, strings like AES/ECB, or Java's default Cipher.getInstance("AES"), which silently means ECB. Semgrep and the Python linter Bandit, which is not the wargame of the same name, both ship rules for it. Dynamically, the repeat_stats function above is itself a detector, because any ciphertext with repeated aligned 16-byte blocks is almost certainly ECB.

Images make the leak easy to see, but the real damage is to structured data. Database columns with repeated values, fixed-format tokens, and session cookies all leak under ECB. The ciphertext reveals equality, which is enough to learn that two users share a password hash, and CryptoHack's ECB Oracle challenge shows it can be turned into byte-at-a-time plaintext recovery. The leak grows with redundancy. High-entropy data like a photograph looks fine under ECB, and that is what makes it dangerous, because it hides the problem.

### 4.2 Why CBC is not the answer: the padding oracle

CBC fixes the pattern leak but gives no integrity, and that opens a different attack. In CBC decryption, each plaintext block is the block cipher decryption of the ciphertext block XORed with the previous ciphertext block. An attacker who can change the previous ciphertext block controls the XOR mask on the decrypted byte, one byte at a time. If the server responds differently to bad padding than to bad data, whether through a different error message, a different status code, or even a different response time, it becomes an oracle. The attacker changes the last byte of the previous block until the padding is accepted, which reveals the last byte of the decrypted block, and so the plaintext byte. Then it repeats for each remaining byte. That is at most 256 guesses per byte, and it needs no key.

This is not hypothetical. It broke ASP.NET in 2010, in the Rizzo and Duong work, and variants like Lucky Thirteen in 2013 and POODLE in 2014 forced changes in TLS. The root cause is that unauthenticated ciphertext gets decrypted and parsed, and the result of that parsing is observable. It maps to CWE-209, information exposure through an error message, together with CWE-353, missing support for an integrity check. The fix is to authenticate before decrypting, meaning encrypt-then-MAC, or to use an AEAD mode like AES-GCM that rejects tampered ciphertext before any padding is examined, and to return one uniform error for every decryption failure. To detect it, I would look for large numbers of near-identical requests that differ only in one ciphertext block, and a spike in decryption failures from a single client, then rate-limit and alert on both.

I analyzed this attack rather than implementing it this week, for scope reasons. An implementation is a candidate for the revised version of this writeup.

### 4.3 Single-byte XOR

The root cause here is a key that is far too small, used as if it were a one-time pad. It maps to CWE-326, inadequate encryption strength, and to CWE-327. The fix is simple. Do not write your own cipher, and use a vetted AEAD with a 128-bit or 256-bit key. This is also worth detecting in the wild, because XOR with a short key is a favorite of malware authors for obfuscating strings, which is why triage tools like xorsearch and CyberChef's XOR brute force exist. I will come back to it in the Week 9 malware triage.

### 4.4 A finding from my own screenshot: incomplete redaction

My first screenshot of Great Snakes had a colored box over the flag in the terminal. But line 9 of the script, the list of ciphertext integers, was still visible in the same image, and chr(o ^ 0x32) was right below it. Anyone reading the post could have recovered the flag in a single line of Python. The redaction hid the output and left the input.

That is CWE-212, improper removal of sensitive information before storage or transfer. It is the same failure as the court filings and government PDFs where a black box sits over text that is still in the document's text layer. The rule I now follow is to redact everything from which the secret can be derived, not only the secret itself, and then to check the redacted image by trying to recover the secret from it. I checked every screenshot in this post that way.

## 5. Reflection and connection to lecture

Symmetric encryption in practice is a primitive plus a mode of operation, and this week showed me why the mode deserves as much attention as the cipher. A few lessons carry forward. Confidentiality is not only about keeping the content secret. Leaking equality, structure, or error behavior is enough to break a system, and ECB leaks structure while a padding oracle leaks one bit per query. Confidentiality without integrity is not secure either, which is why modern designs default to AEAD, and that leads straight into the second half of this module on hashes, MACs, and signatures. Small keyspaces fall to brute force no matter how good the algorithm is, and the same arithmetic will matter when I reach RSA parameter choices in the next set.

For tooling I used Python 3 with pycryptodome and Pillow in a virtual environment on Kali, VS Code, gdb with pwndbg, and the CryptoHack and OverTheWire platforms. One practical note from setup. Kali ships Python 3.14, which blocks system-wide pip install under PEP 668, so all of my tooling lives in a virtual environment at ~/ctf/venv, which also keeps the VM reproducible.

## 6. Progress and next steps

So far I have set up the lab VM and toolchain with a baseline snapshot, completed the OverTheWire Bandit warm-up, built the ECB versus CBC leakage demonstration, and solved CryptoHack's Great Snakes. I analyzed the CBC padding-oracle decryption without implementing it. Still ahead, for the revised writeup, are the rest of CryptoHack's General sets covering Encoding and XOR, the AES-structure sets, the RSA and public-key and Hashes sets, and the Week 3 weak-RSA and hash and signature-flaw exploits.

The contract anticipates iterating on each writeup after faculty feedback, so I will revise this one as I finish the remaining Module A1 challenges.
