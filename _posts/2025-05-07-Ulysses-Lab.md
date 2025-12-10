---
title: "Ulysses Lab - SSH Brute Force Analysis"
date: 2025-07-04 12:00:00 +0700
categories: [CTF, Forensics]
tags: [ssh, brute-force, linux, memory-forensics, volatility]
image:
  path: /assets/img/posts/Ulysses-Lab/banner.png
  alt: Ulysses Lab
---
## Giới thiệu

**Difficulty**: Medium  
**Category**: Endpoint  
**Tool**: Volatility 2

Bài lab phân tích tấn công brute force SSH và khai thác lỗ hổng Exim4.

## Q1: The attacker was performing a Brute Force attack. What account triggered the alert?

Kiểm tra file log trong `/var/log`, ta thấy có dấu hiệu bruteforce

![image.png](/assets/img/posts/Ulysses-Lab/image.png)

User `ulysses` đã brute force ssh từ ip 192.168.56.1 và cổng là 34431

## Q2: During investigating the logs. How many failed login attempts were alerted by the same user?

```python
Failed none for invalid user ulysses from 192.168.56.1 port 34441 ssh2
```

| Thành phần | Ý nghĩa |
| --- | --- |
| `Failed none` | Giao thức SSH cho phép phương thức xác thực là `"none"` – nghĩa là **không cung cấp thông tin gì** (chỉ kết nối thử). Hệ thống từ chối. |
| `for invalid user ulysses` | User `ulysses` không tồn tại trên hệ thống (invalid user). |
| `from 192.168.56.1` | IP thực hiện kết nối. |
| `port 34441` | Cổng nguồn của client (random ephemeral port). |
| `ssh2` | Phiên bản giao thức SSH được dùng là SSH-2. |

Chính vì vậy ngoài đếm failed password, ta còn đếm cả failed none (kết nối thử đầu tiên nhưng bị từ chối)

![image.png](/assets/img/posts/Ulysses-Lab/image%201.png)

## Q3: What kind of system runs on the targeted server?

<!-- ![image.png](/assets/img/posts/Ulysses-Lab/image%202.png) -->

Do không có `/etc/os-release` nên ta vào `/etc/issue`

![image.png](/assets/img/posts/Ulysses-Lab/image%203.png)

**Answer**: Debian GNU/Linux 5.0

### Các file quan trọng để xác định OS

- **`issue`**: Chứa thông tin OS hiển thị khi login
- **`os-release`**: Thông tin chi tiết về OS (name, version, ID)
- **`lsb-release`**: Thông tin theo chuẩn Linux Standard Base
- **`passwd`**: Thông tin user account
- **`fstab`**: Cấu hình filesystem
- **`hostname`**: Tên máy
- **`network/interfaces`**: Cấu hình network
- **`resolv.conf`**: Cấu hình DNS

## Q4: What is the victim's IP address?

![image.png](/assets/img/posts/Ulysses-Lab/image%204.png)

### `/var/lib/dhcp`

Nơi lưu **thông tin thuê địa chỉ IP** khi máy sử dụng DHCP client:
- `dhclient.leases` – Lịch sử thuê IP từ DHCP server
- `dhclient.pid` – PID của tiến trình DHCP client

Hoặc sử dụng plugin `net_stat`:

```bash
vol2 -f victoria-v8.memdump.img --profile=LinuxDebian5_26x86 linux_netstat
```

![image.png](/assets/img/posts/Ulysses-Lab/image%205.png)

**Answer**: 192.168.56.102

## Q5: What are the attacker's two IP addresses? Format: comma-separated in ascending order

Từ ảnh trên ta thấy có 2 IP. Kiểm tra thêm trong `/var/log/exim4` (log của Mail Transfer Agent):

![image.png](/assets/img/posts/Ulysses-Lab/image%206.png)
![image.png](/assets/img/posts/Ulysses-Lab/image%207.png)

**Answer**: 192.168.56.1, 192.168.56.105

## Q6: What is the "nc" service PID number that was running on the server?

![image.png](/assets/img/posts/Ulysses-Lab/image%208.png)

**Answer**: 2893

## Q7: What service was exploited to gain access to the system? (one word)

![image.png](/assets/img/posts/Ulysses-Lab/image%209.png)

Attacker dùng `/bin/sh` để tải file `c.pl` (script automation) và lưu vào `/tmp`.

**Answer**: exim4

### Exim4 là gì?

Mail Transfer Agent (MTA) được sử dụng rộng rãi trên Unix/Linux để routing, delivering và quản lý email.

## Q8: What is the CVE number of exploited vulnerability?

https://www.exploit-db.com/exploits/15725

**Answer**: CVE-2010-4344

## Q9: During this attack, the attacker downloaded two files to the server. Provide the name of the compressed file.

![image.png](/assets/img/posts/Ulysses-Lab/image%2010.png)

**Answer**: rk.tar

## Q10: Two ports were involved in the process of data exfiltration. Provide the port number of the highest one.

Từ Q4 → **Answer**: 8888

## Q11: Which port did the attacker try to block on the firewall?

![image.png](/assets/img/posts/Ulysses-Lab/image%2011.png)

Xem trong `rk.tar`, ta thấy:

```bash
echo "/usr/sbin/iptables -I OUTPUT 1 -p tcp --dport 45295 -j DROP" >> /etc/rc.d/rc.local
echo "/usr/sbin/iptables -I OUTPUT 1 -p tcp --dport 45295 -j DROP" >> /etc/init.d/xfs3
iptables -I OUTPUT 1 -p tcp --dport 45295 -j DROP
```

Attacker cố gắng block outgoing traffic đến port 45295:
1. Thêm rule vào startup scripts để persist qua reboot
2. Áp dụng rule ngay lập tức bằng iptables
3. `-j DROP` làm firewall drop packet mà không thông báo

**Answer**: 45295
