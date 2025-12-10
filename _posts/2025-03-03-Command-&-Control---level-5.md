---
title: "Command & Control - Level 5 - Memory Forensics & Password Hash Extraction"
date: 2025-07-04 12:00:00 +0700
categories: [CTF, Memory Forensics]
tags: [volatility, hashdump, sam, john-the-ripper, password-cracking]
image:
  path: /assets/img/posts/NLTM/banner.png
  alt: rootme
---

## Giới thiệu

**Difficulty**: Medium  
**Category**: Endpoint  
**Tools**: Volatility, John the Ripper

Bài lab phân tích memory dump để trích xuất và crack password hash từ Windows SAM.

## Statement
Berthier, the malware seems to be manually maintened on the workstations. Therefore it’s likely that the hackers have found all of the computers’ passwords.
Since ACME’s computer fleet seems to be up to date, it’s probably only due to password weakness. John, the system administrator doesn’t believe you. Prove him wrong!

Find john password.

## Windows Hashdump Plugin

The `windows.hashdump.Hashdump` plugin in **Volatility** (specifically for Windows memory analysis) is used to **dump password hashes** from memory.

`hashdump` pulls password hashes from:

- **SAM (Security Account Manager)** hive
- **SYSTEM** hive (for the SYSKEY used to decrypt hashes)

The plugin looks for registry hives in memory, extracts the necessary keys, and decrypts the hashes.

## Trích xuất Password Hashes

```bash
Administrator   500     aad3b435b51404eeaad3b435b51404ee        31d6cfe0d16ae931b73c59d7e0c089c0
Guest   501     aad3b435b51404eeaad3b435b51404ee        31d6cfe0d16ae931b73c59d7e0c089c0
John Doe        1000    aad3b435b51404eeaad3b435b51404ee        b9f917853e3dbf6e6831ecce60725930
```

## Crack Password với John the Ripper

```bash
┌──(kali㉿kali)-[~/forensics/ch2]
└─$ john --format=NT pass.txt 
Created directory: /home/kali/.john
Using default input encoding: UTF-8
Loaded 1 password hash (NT [MD4 128/128 AVX 4x3])
Warning: no OpenMP support for this hash type, consider --fork=4
Proceeding with single, rules:Single
Press 'q' or Ctrl-C to abort, almost any other key for status
Almost done: Processing the remaining buffered candidate passwords, if any.
Proceeding with wordlist:/usr/share/john/password.lst
passw0rd         (?)     
1g 0:00:00:00 DONE 2/3 (2025-08-06 11:21) 100.0g/s 211200p/s 211200c/s 211200C/s pretty..celtic
Use the "--show --format=NT" options to display all of the cracked passwords reliably
Session completed.
```

**Password**: `passw0rd`

## Tham khảo

- [Volatility Documentation](https://volatility3.readthedocs.io/)
-