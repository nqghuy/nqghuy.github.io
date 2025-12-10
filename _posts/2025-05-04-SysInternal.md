---
title: "SysInternal - Malware Analysis"
date: 2025-07-04 12:00:00 +0700
categories: [CTF, Forensics]
tags: [malware-analysis, amcache, windows, forensics, virustotal]
image:
  path: /assets/img/posts/SysInternal/banner.png
  alt: SysInternal Lab
---

## Giới thiệu

**Difficulty**: Easy  
**Category**: Endpoint  
**Tools**: Amcache Parser, FTK Imager, VirusTotal

Bài lab phân tích malware giả mạo SysInternals Suite.

## Q1: What was the malicious executable file name that the user downloaded?

Tìm trong các thư mục Downloads của các user

![image.png](/assets/img/posts/SysInternal/image.png)

Ta tìm thấy file SysInternal.exe trong user Public

File quá bé, cộng với việc SysInternal được Microsoft phát triển, sử dụng dưới nhiều utilities chứ không phải file đớn độc exe -> malware

## Q2: What is the SHA1 hash value of the malware?

Ta thấy trong FTK Imager, file SysInternals.exe toàn 0, có thể file đã bị xóa.

### Registry hive là gì?

**Registry hive** trong Windows là một **tệp dữ liệu lớn** chứa một phần của Windows Registry – nơi hệ điều hành lưu tất cả các cấu hình và thông tin quan trọng.

- **Registry** = cơ sở dữ liệu trung tâm của Windows (chứa cài đặt hệ thống, người dùng, phần mềm, thiết bị...).
- **Hive** = một "kho" lớn (một tập tin `.dat` hoặc `.hve`) lưu trữ một nhánh của Registry.

### Đặc điểm của Registry hive:

- Mỗi hive là **một file trên ổ đĩa**, Windows nạp nó vào bộ nhớ khi khởi động.
- Ví dụ:
    - `C:\Windows\System32\config\SYSTEM` → chứa **HKLM\SYSTEM**
    - `C:\Windows\System32\config\SOFTWARE` → chứa **HKLM\SOFTWARE**
    - `C:\Users\<User>\NTUSER.DAT` → chứa **HKEY_CURRENT_USER**
- **AmCache.hve** cũng là một registry hive, lưu **metadata về các file đã chạy** trên hệ thống (đường dẫn, hash, timestamps).
- Vì nó là một hive, bạn không mở trực tiếp được mà cần công cụ chuyên dụng (Registry Viewer, AmCacheParser, v.v.).

### AmCache là gì?

**AmCache** là một **registry hive** trong Windows, lưu lại thông tin về các chương trình đã từng chạy trên hệ thống.

Nó lưu những gì?

- **Đường dẫn file** (full path).
- **Hash của file** (thường là SHA1).
- **Thông tin về phiên bản** (tên sản phẩm, công ty, version).
- **Timestamps** (lần chạy đầu tiên, lần chạy gần nhất).

![image.png](/assets/img/posts/SysInternal/image%201.png)

Sử dụng AmCacheParser

![image.png](/assets/img/posts/SysInternal/image%202.png)

File Amcache.hve lưu ở `Windows\appcompat\programs\Amcache.hve`

## Q3: What is the malware's family?

![image.png](/assets/img/posts/SysInternal/image%203.png)

## Q4: What is the first mapped domain's Fully Qualified Domain Name (FQDN)?

![image.png](/assets/img/posts/SysInternal/image%204.png)

## Q5: The mapped domain is linked to an IP address. What is that IP address?

Ta kiểm tra log của PowerShell

![image.png](/assets/img/posts/SysInternal/image%205.png)

Nằm ở `IEUser\AppData\Roaming\Microsoft\Windows\Powershell\PSreadline\ConsoleHost_history.txt`

- File **hosts** dùng để ánh xạ tên miền (FQDN) sang địa chỉ IP trước khi hệ thống thực hiện truy vấn DNS.
- Malware đã thêm hai ánh xạ:
    - `www.malware430.com` → `192.168.15.10`
    - `www.sysinternals.com` → `192.168.15.10`
- Khi người dùng hoặc hệ thống truy cập những domain này, máy sẽ **bỏ qua DNS thực** và kết nối thẳng đến IP 192.168.15.10 do attacker kiểm soát.

### Tại sao nguy hiểm?

- Cho phép kẻ tấn công **chuyển hướng traffic** đến máy chủ độc hại, có thể:
    - Lừa người dùng tải thêm malware.
    - Thu thập thông tin đăng nhập.
    - Ngăn chặn truy cập vào website thật (như `sysinternals.com`).

## Q6: What is the name of the executable dropped by the first-stage executable?
www.malware430.com như câu 5
## Q7: What is the name of the service installed by 2nd stage executable?

![image.png](/assets/img/posts/SysInternal/image%206.png)

- Từ báo cáo VirusTotal, trong tab **Behavior**, ta thấy file **SysInternals.exe** thực thi và tự copy vào thư mục tạm:
    
    ```
    C:\Users\<USER>\AppData\Local\Temp\Sysinternals.exe
    ```
    
- Sau đó nó chạy lệnh:
    
    ```
    "C:\Windows\System32\cmd.exe" /C c:\Windows\vmtoolsIO.exe -install && net start VMwareIOHelperService && sc config VMwareIOHelperService start= auto
    ```
    
- Lệnh này:
    - **Cài đặt file mới**: `vmtoolsIO.exe`.
    - **Tạo service**: `VMwareIOHelperService` để đảm bảo persistence.
- Việc sử dụng `net start` và `sc config` cho thấy malware muốn chạy **vmtoolsIO.exe** mỗi khi khởi động hệ thống.
