---
title: "Windows - LDAP User KerbeRoastable"
date: 2025-07-04 12:00:00 +0700
categories: [CTF, Forensics]
tags: [ldap, kerberoasting, active-directory, windows]
image:
  path: /assets/img/posts/Windows-LDAP/banner.png
  alt: Windows LDAP User KerbeRoastable
---

## Giới thiệu

Bài lab từ Root-Me về tìm kiếm user có thể bị Kerberoasting trong LDAP.

**Độ khó**: Easy  
**Category**: Network  
**Tool**: ldap2json

**Đề bài**: Tìm email của user có thể bị Kerberoasting.

## LDAP là gì?

LDAP (Lightweight Directory Access Protocol) là giao thức truy cập và quản lý **dịch vụ thư mục** - lưu trữ thông tin người dùng, nhóm, máy chủ trong mạng.

Cấu trúc dữ liệu dạng cây phân cấp:

```
dn: cn=John Doe,ou=People,dc=example,dc=com
```

- `cn=John Doe`: Common Name
- `ou=People`: Organizational Unit  
- `dc=example,dc=com`: Domain Component

## Kerberoasting là gì?

Kỹ thuật tấn công để crack password của account có SPN (Service Principal Name):

1. Request TGS ticket cho service có SPN
2. Extract ticket (được mã hóa bằng password hash của service account)
3. Crack hash offline bằng hashcat/john
4. Lấy được password của service account

## Phân tích

Sử dụng tool ldap2json để phân tích file LDAP:

```bash
python3 analysis.py -f ch31.json
```

## Các lệnh hữu ích

| Lệnh | Chức năng |
|------|-----------|
| `searchbase` | Hiển thị/thay đổi LDAP search base |
| `object_by_property_name` | Tìm object theo tên thuộc tính |
| `object_by_property_value` | Tìm object theo giá trị thuộc tính |
| `object_by_dn` | Tìm object theo Distinguished Name |
| `search_for_kerberoastable_users` | Tìm user có SPN (Kerberoastable) |
| `search_for_asreproastable_users` | Tìm user có DONT_REQ_PREAUTH |


### Tìm user có thể Kerberoasting

```bash
[]> search_for_kerberoastable_users
[CN=Alexandria,CN=Users,DC=ROOTME,DC=local] => servicePrincipalName
 - ['HTTP/SRV-RDS.rootme.local']
```

User `Alexandria` có SPN tức TGS được mã hóa bằng key là mật khẩu của `Alexandria` → có thể bị Kerberoasting. Flag yêu cầu tìm `the email address of the Kerberoastable user.`

### Lấy thông tin chi tiết

```bash
[]> object_by_dn CN=Alexandria,CN=Users,DC=ROOTME,DC=local
{
    "cn": "Alexandria",
    "sn": "Newton",
    "displayName": "Alexandria NEWTON",
    "sAMAccountName": "a.newton",
    "servicePrincipalName": [
        "HTTP/SRV-RDS.rootme.local"
    ],
    "mail": "alexandria.newton@rootme.local"
}
```

**Flag**: `alexandria.newton@rootme.local`

Một bài không khó để thực hiện nhưng khó về mặt lí thuyết.