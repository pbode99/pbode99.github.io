---
title: "Writeup 2: Authentication and Access Control"
date: 2026-10-15 21:00:00 -0400
categories: [CTF Writeups]
tags: [authentication, access-control, hashcat, john, portswigger, burp]
---

## Problem summary and threat context

This writeup covers two sides of the same question. Who are you, and what are you allowed to do. The authentication work looked at how passwords are stored and broken offline, and how a login form can quietly reveal which accounts exist. The access control work looked at what happens after a request reaches the server and nobody checks whether the person sending it should be allowed. I did the cracking on an isolated Kali VM and the web work on PortSwigger's training labs, each of which runs a private instance for the exercise. Nothing here touched a live or third party system.

## Attacker walkthrough

I began with offline password cracking. I generated my own MD5 hashes from weak passwords so I would know the answers in advance, saved them to a file, and ran them against the rockyou wordlist. The first three fell in about a second each. The passwords password123, iloveyou, and dragon all sit in rockyou word for word, so a plain wordlist attack finds them right away.

![John cracked all three weak hashes](/assets/img/writeup2/pwcrack-cracked.png)

My first real obstacle was the tool. hashcat refused to run because the VM has no GPU and no OpenCL backend, so it had nothing to compute on. I lost a few minutes to that before moving to John the Ripper, which runs on the CPU with no extra setup. The problem taught me something worth keeping. Cracking is normally a GPU job, and a real attacker has one, so my slow CPU run actually understates how fast this is in the real world.

Then I made a harder target. Dragon2024! is a capitalized word with a year and a symbol, the kind of password people assume is strong. A plain wordlist missed it. One small mistake slowed me down first. I had hashed Dragon2024! to the screen but never saved it to a file, so my first attempt failed with a no such file error, and I had to write the hash into its own file before John could read it. Once it could, John's best64 ruleset, which applies 64 common transformations to each word, finished and cracked nothing.

![best64 failed to crack Dragon2024!](/assets/img/writeup2/pwcrack-dragon-fail.png)

That failure to crack was the useful result. The password is still reachable in theory, since the keyspace is finite, but a modest ruleset never reached it in reasonable time. Adding a symbol to a dictionary word is not what makes a password hard.

The next piece was a PortSwigger login form, and it was also where I learned Burp Suite, which I had never used. I captured a failed login, sent it to Intruder, marked the username field as the payload position, and loaded the lab's candidate username list. When the run finished I sorted by response length. Every response came back at 3352 bytes except one. The username ftp returned 3354.

![Username ftp stands out by response length](/assets/img/writeup2/enum-ftp-length.png)

Two bytes was the whole vulnerability. The form answered Invalid username for fake accounts and Incorrect password for the real one, and those two messages differ by exactly that much. I fixed the username to ftp, marked the password as the payload position, loaded the password list, and looked for the one response that returned a 302 redirect rather than a 200. The password was monitoring. Logging in with those credentials solved the lab.

![Lab solved after logging in as ftp](/assets/img/writeup2/enum-solved.png)

Access control was the most direct of the three. The first lab had an admin page that was not linked from anywhere and was protected only by being hard to find. I checked robots.txt, the file that is supposed to tell crawlers what to skip, and it named the exact path it was trying to keep quiet. My first try I typed /robots with no extension and got a blank page, because the file is robots.txt and the name has to be exact. With the right path I read the disclosure.

![robots.txt disclosing the admin path](/assets/img/writeup2/admin-robots.png)

I then visited /administrator-panel directly. The page loaded with no login at all. I deleted the target user and the lab was solved.

![Admin action succeeds with no authentication](/assets/img/writeup2/admin-solved.png)

The second lab made the same failure concrete in a different way. Logged in as a low privilege user, my own account page used the URL my-account?id=wiener. I changed wiener to carlos. The page returned another user's account details and API key, with nothing changed but that one parameter. The server read the id from the request and trusted it, rather than checking whether my session owned the account I asked for.

![Changing the id parameter exposes another user's data](/assets/img/writeup2/idor-carlos.png)

## Defender's analysis

The password findings come down to how the hashes were built. MD5 is fast, which is a flaw for password storage, because a defender wants the hash to be slow enough to make guessing expensive. The hashes were also unsalted, so identical passwords produce identical hashes and precomputed tables become useful. This is CWE-916, use of a weak hash, together with CWE-759 for the missing salt. The fix is a slow memory hard algorithm such as bcrypt, scrypt, or Argon2, with a unique random salt for every password. Length requirements and screening new passwords against known breach lists do far more than forcing a symbol, as Dragon2024! showed.

The login form leaked account existence through different responses for valid and invalid usernames, which is CWE-204. An attacker uses that to build a list of real accounts and then only guesses passwords against those. The fix is one identical message for every failed login, with the same status code and the same length. Response time matters too, because a valid username that reaches the password check can take longer to answer, and that timing difference is its own side channel. That idea connects straight to the side channel material coming up later in the course.

Neither login applied any rate limiting. I sent a hundred password guesses with no friction at all, which is CWE-307. A real system throttles attempts per account and per address, locks accounts after repeated failures, and adds a challenge once traffic looks automated.

The access control labs share one root cause. The admin page relied on secrecy rather than a check, and robots.txt removed the secrecy. The account page trusted an id the client controlled. Both are broken access control, CWE-284, with the id case also matching CWE-639. The server has to confirm, on every request, that the authenticated session is allowed to reach that function and owns that object. Access should be denied by default, and robots.txt should never hold a path that is not already safe to reveal, since it is a hint to attackers and not a control.

## Reflection

The thread running through all of this is the server trusting the client. The login trusted its own error text to stay quiet and it did not. The account page trusted a parameter the user could edit. The admin page trusted that nobody would find it. Authentication answers who you are and access control answers what you may do, and each failure here was a check that belonged on the server and was missing. That framing matched the lecture material on both topics and gave me a single question to carry into the rest of the course. Where does the server decide to trust the request.

## References

Hashcat. hashcat advanced password recovery. https://hashcat.net/hashcat/

Openwall. John the Ripper password cracker. https://www.openwall.com/john/

PortSwigger. Username enumeration via different responses. https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-different-responses

PortSwigger. Unprotected admin functionality. https://portswigger.net/web-security/access-control/lab-unprotected-admin-functionality

PortSwigger. User ID controlled by request parameter. https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter

MITRE. CWE-204, CWE-284, CWE-307, CWE-639, CWE-759, CWE-916. https://cwe.mitre.org/
