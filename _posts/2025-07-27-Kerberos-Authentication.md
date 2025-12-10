---
title: "Kerberos Authentication - Network Protocol Analysis"
date: 2025-07-04 12:00:00 +0700
categories: [CTF, Network Forensics]
tags: [kerberos, wireshark, authentication, active-directory, hashcat]
image:
  path: /assets/img/posts/Kerberos-Authentication/banner.png
  alt: Kerberos Authentication
---
<!-- ![alt text](image.png) -->
<!-- ![alt text](image.png) -->
## Giới thiệu

**Difficulty**: Medium  
**Category**: Network  
**Tools**: Wireshark, hashcat

Bài lab phân tích giao thức Kerberos authentication và crack pre-authentication hash.

**URL**: https://www.root-me.org/en/Challenges/Network/Kerberos-Authentication?lang=en

**Few things to note:**

Client has Client Secret Key.

Application Server has Service Secret Key.

Key Distribution Centre (KDC) have Ticket Granting Server (TGS) Secret Keys, Client Secret Keys, Service Secret Keys.

## Lí thuyết

![image.png](/assets/img/posts/Kerberos-Authentication/image.png)

[https://medium.com/@gsanjay1708/kerberos-authentication-14632c2dec5f](https://medium.com/@gsanjay1708/kerberos-authentication-14632c2dec5f)

[https://medium.com/@robert.broeckelmann/kerberos-wireshark-captures-a-windows-login-example-151fabf3375a](https://medium.com/@robert.broeckelmann/kerberos-wireshark-captures-a-windows-login-example-151fabf3375a)

[https://beta.hackndo.com/kerberos/](https://beta.hackndo.com/kerberos/)

![image.png](/assets/img/posts/Kerberos-Authentication/image%201.png)

Đầu tiên sẽ là TCP kết nối 3 bước và pre-auth

![image.png](/assets/img/posts/Kerberos-Authentication/image%202.png)

AS-REQ đầu tiên, ta thấy được cname, realm. etype,…

![image.png](/assets/img/posts/Kerberos-Authentication/image%203.png)

server gửi lại Kerberos error do yêu cầu pre-auth

Server nhắc client cần gửi timestamp được mã hóa bằng key người dùng

![image.png](/assets/img/posts/Kerberos-Authentication/image%204.png)

Tiếp đến là gói FIN, ACK RST để đóng kết nối.

Tiếp tục là 3 gói tcp mở kết nối và `AS-REQ`, `AS-REP`

![image.png](/assets/img/posts/Kerberos-Authentication/image%205.png)

![image.png](/assets/img/posts/Kerberos-Authentication/image%206.png)

![image.png](/assets/img/posts/Kerberos-Authentication/image%207.png)

Client sẽ mã hóa timestamp của mình bằng `client key` . KDC (KEY DISTRIBUTED CENTER) sẽ tra bảng hash để giải mã. Nếu thất bại thì không xác định client.

Nếu thành công

![image.png](/assets/img/posts/Kerberos-Authentication/image%208.png)

### Phân tích AS-REP

![image.png](/assets/img/posts/Kerberos-Authentication/image%209.png)

ticket→enc-part: `7fc0db` được mã hóa bởi key của TGS, để server kiểm tra

enc→part: `3eea` client đọc được, được mã hóa bởi client key chứa `session key`(TGS ID) dùng trong TGS REQUEST (chứa session key)

Tiếp tục ngắt kết nối và thiết lập kết nối mới

![image.png](/assets/img/posts/Kerberos-Authentication/image%2010.png)

![image.png](/assets/img/posts/Kerberos-Authentication/image%2011.png)

Client gửi:

TGT: `7fc0` mà client nhận lúc trước

Authenticator: message containing his name, and a timestamp, all encrypted with the session key he has in his possession. được mã hóa bằng `session key` nằm trong enc→part ở trên

Server sau đó decrypt Authenticator bằng `session key`. Vân vân và mây mây

![image.png](/assets/img/posts/Kerberos-Authentication/image%2012.png)

Vậy cuối cùng crack client pass bằng cách nào. Chính là phần timestamp client mã hóa bằng client key ở `as_req`

## Crack Kerberos Pre-Authentication

```bash
┌──(nqghuy㉿DESKTOP-AJTP5JK)-[~/forensics/kerberos/ch29]
└─$ hashcat -hh | grep -i "kerberos"
  19600 | Kerberos 5, etype 17, TGS-REP                              | Network Protocol
  19800 | Kerberos 5, etype 17, Pre-Auth                             | Network Protocol
  28800 | Kerberos 5, etype 17, DB                                   | Network Protocol
  32100 | Kerberos 5, etype 17, AS-REP                               | Network Protocol
  19700 | Kerberos 5, etype 18, TGS-REP                              | Network Protocol
  19900 | Kerberos 5, etype 18, Pre-Auth                             | Network Protocol
  28900 | Kerberos 5, etype 18, DB                                   | Network Protocol
  32200 | Kerberos 5, etype 18, AS-REP                               | Network Protocol
   7500 | Kerberos 5, etype 23, AS-REQ Pre-Auth                      | Network Protocol
  13100 | Kerberos 5, etype 23, TGS-REP                              | Network Protocol
  18200 | Kerberos 5, etype 23, AS-REP                               | Network Protocol
```

https://hashcat.net/wiki/doku.php?id=example_hashes

xem format

```bash
┌──(nqghuy㉿DESKTOP-AJTP5JK)-[~/forensics/kerberos/ch29]
└─$ hashcat -a 0 -m 19900 timestamp.txt /usr/share/wordlists/rockyou.txt
hashcat (v7.0.0) starting

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, LLVM 18.1.8, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
============================================================================================================================================
* Device #01: cpu-haswell-12th Gen Intel(R) Core(TM) i5-1240P, 2870/5740 MB (1024 MB allocatable), 16MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256
Minimum salt length supported by kernel: 0
Maximum salt length supported by kernel: 256

INFO: All hashes found as potfile and/or empty entries! Use --show to display them.
      For more information, see https://hashcat.net/faq/potfile

Started: Sat Aug  2 10:45:27 2025
Stopped: Sat Aug  2 10:45:27 2025

┌──(nqghuy㉿DESKTOP-AJTP5JK)-[~/forensics/kerberos/ch29]
└─$ hashcat -a 0 -m 19900 timestamp.txt /usr/share/wordlists/rockyou.txt --show
$krb5pa$18$hashcat$william.dupond@CATCORP.LOCAL$fc8bbe22b2c967b222ed73dd7616ea71b2ae0c1b0c3688bfff7fecffdebd4054471350cb6e36d3b55ba3420be6c0210b2d978d3f51d1eb4f:kittycat12
```

crack thành công

**Password**: `kittycat12`

## Tham khảo

- [Kerberos Authentication](https://medium.com/@gsanjay1708/kerberos-authentication-14632c2dec5f)