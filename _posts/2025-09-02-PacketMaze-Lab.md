---
title: "PacketMaze Lab - Network Traffic Analysis"
date: 2025-07-04 12:00:00 +0700
categories: [CTF, Network Forensics]
tags: [wireshark, ftp, tls, ipv6, dns, pcap]
image:
  path: /assets/img/posts/PacketMaze-Lab/banner.png
  alt: PacketMaze Lab
---
## Giới thiệu

**Difficulty**: Easy  
**Category**: Network  
**Tools**: Wireshark

Bài lab phân tích network traffic để trả lời các câu hỏi về FTP, DNS, TLS và các giao thức mạng.

## Q1: What is the FTP password?

![image.png](/assets/img/posts/PacketMaze-Lab/image.png)

## Q2: What is the IPv6 address of the DNS server used by `192.168.1.26`?

![image.png](/assets/img/posts/PacketMaze-Lab/image%201.png)

frame thứ 474 là frame gửi request

![image.png](/assets/img/posts/PacketMaze-Lab/image%202.png)

đáp lại yêu cầu, ta suy ra được dns server

### Link-local IPv6 Address là gì?

- Tất cả thiết bị dùng IPv6 đều **tự động gán** cho mình một địa chỉ bắt đầu bằng `fe80::`.
- Đây là **địa chỉ chỉ dùng để giao tiếp trong cùng mạng LAN** (cùng subnet, cùng switch).
- Không thể định tuyến ra Internet.

➡️ Vì vậy, `fe80::c80b:adff:feaa:1db7` là **địa chỉ nội bộ tạm thời của DNS server**, không phải DNS toàn cục như `8.8.8.8`.

## Q3: What domain is the user looking up in packet `15174`?

quá dễ rồi 

## Q4: How many UDP packets were sent from `192.168.1.26` to `24.39.217.246`?

![image.png](/assets/img/posts/PacketMaze-Lab/image%203.png)

10 cái

## Q5: What is the MAC address of the system under investigation in the PCAP file?

![image.png](/assets/img/posts/PacketMaze-Lab/image%204.png)

Phân tích ethernet

## Q6: What was the camera model name used to take picture `20210429_152157.jpg`?

export FTP-DATA, exiftool là xong

## Q7: What is the public key of the server certificate used in the TLS session with the session ID: `da4a0000342e4b73459d7360b4bea971cc303ac18d29b99067e46d16cc07f4ff`?

![image.png](/assets/img/posts/PacketMaze-Lab/image%205.png)

**TLS (Transport Layer Security)** là một **giao thức mã hóa** giúp đảm bảo:

1. **Confidentiality (Bí mật)**: Dữ liệu được **mã hóa**, kẻ tấn công không đọc được.
2. **Integrity (Toàn vẹn)**: Dữ liệu không bị thay đổi trong quá trình truyền.
3. **Authentication (Xác thực)**: Xác minh bạn đang nói chuyện với đúng máy chủ (không phải kẻ mạo danh).

### Các bước cơ bản:

1. **Client Hello**:
    - Trình duyệt gửi một lời chào đến server: "Tôi muốn bắt tay mã hóa"
    - Kèm theo: danh sách thuật toán mã hóa hỗ trợ, session ID, và nonce (số ngẫu nhiên).
2. **Server Hello**:
    - Server phản hồi: "Tôi chọn thuật toán này"
    - Kèm theo **chứng chỉ số (certificate)** chứa **public key**
    - Có thể kèm session ID, nonce, v.v.
3. **Xác thực**:
    - Trình duyệt kiểm tra chứng chỉ số xem có hợp lệ không (qua CA - Certificate Authority)
4. **Key Exchange**:
    - Cả hai bên trao đổi để tạo ra một **"shared secret" (bí mật chung)** – dùng để mã hóa dữ liệu tiếp theo.
    - Có thể dùng các cơ chế như:
        - RSA (truyền key mã hóa bằng public key)
        - Diffie-Hellman / ECDHE (an toàn hơn, tạo key chung mà không truyền trực tiếp)
5. **Finished**:
    - Sau khi key đã được chia sẻ, mọi dữ liệu sau đó đều được **mã hóa đối xứng** (nhanh hơn).

## Q8: What is the first `TLS 1.3` client random that was used to establish a connection with `protonmail.com`?

![image.png](/assets/img/posts/PacketMaze-Lab/image%206.png)

![image.png](/assets/img/posts/PacketMaze-Lab/image%207.png)

## Q9: Which country is the `FTP server's MAC address` registered in?

![image.png](/assets/img/posts/PacketMaze-Lab/image%208.png)

ftp server là 192.168.1.20

![image.png](/assets/img/posts/PacketMaze-Lab/image%209.png)

Mac là 08:00:27:a6:1f:86

![image.png](/assets/img/posts/PacketMaze-Lab/image%2010.png)

Mỹ tho

## Q10: What time was a `non-standard folder` created on the FTP server on the 20th of April?

![image.png](/assets/img/posts/PacketMaze-Lab/image%2011.png)

lọc với `ftp-data` và command LIST

![image.png](/assets/img/posts/PacketMaze-Lab/image%2012.png)

20/4 có dir ftp

## Q11: What URL was visited by the user and connected to the IP address `104.21.89.171`?

dễ

