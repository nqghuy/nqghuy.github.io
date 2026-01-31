---
title: "Data Stolen"
date: 2026-01-25 12:00:00 +0700
categories: [CTF, Forensics]
tags: [network]
image:
  path: /assets/img/posts/Data_Stolen/banner.png
---

1 thử thách CTF forensics đến từ VSL. Thử thách lần này liên quan đến network forensics
| Some data has been transmitted externally without authorization. Can you find it?

Đầu tiên ta sẽ xem các giao thức được sử dụng.
![alt text](/assets/img/posts/Data_Stolen/image.png)

Ta kiểm tra conversations khả nghi
![alt text](/assets/img/posts/Data_Stolen/image-1.png)
2 ip 172.26.31.148 và 185.125.190.26 có số lượng traffic nhiều hơn hẳn

Kiểm tra http
![alt text](/assets/img/posts/Data_Stolen/image-2.png)
Nhận thấy giao method POST, key rất khả nghi nên mình tiến hành extract
```
nguyen@nqghuy:~/CTF/forenshits/http$ cat uploa*
NHR0NGM=OKa190M2M=OKaG4xcXUzfQ==OK
```
bỏ ok do phản hồi đi và giải mã base64 -d ta có được:
```
nguyen@nqghuy:~/CTF/forenshits/http$ echo "NHR0NGM=a190M2M=aG4xcXUzfQ==" | base64 -d
4tt4ck_t3chn1qu3}
```
Ta đã có mẩu flag cuối. Như vậy, ta nhận thấy ip 172.26.31.148 đang cố gắng truyền data cho 10.23.11.27
Tiếp theo đến với MDNS (Multicast DNS)

![alt text](/assets/img/posts/Data_Stolen/image-3.png)
Ta thấy có dns exfil ở đây
```
nguyen@nqghuy:~/CTF/forenshits$ tshark -r challenge.pcapng -Y "dns.flags.response == 0 && ip.addr == 172.26.31.148 && ip.addr == 10.23.11.27" -T fields -e dns.qry.name
VlNMe24z.vsl.com
www.google.com
time.cloudflare.com
www.reddit.com
dHcwcmtf.vsl.com
github.com
www.youtube.com
dHVubjM=.vsl.com
www.google.com
time.cloudflare.com
www.wikipedia.org
nguyen@nqghuy:~/CTF/forenshits$ tshark -r challenge.pcapng -Y "dns.flags.response == 0 && ip.addr == 172.26.31.148 && ip.addr == 10.23.11.27" -T fields -e dns.qry.name | grep vsl
VlNMe24z.vsl.com
dHcwcmtf.vsl.com
dHVubjM=.vsl.com
nguyen@nqghuy:~/CTF/forenshits$ echo "VlNMe24zdHcwcmtfdHVubjM=" | base64 -d
VSL{n3tw0rk_tunn3
```
Ta đã có mảnh flag đầu tiên
![alt text](/assets/img/posts/Data_Stolen/image-4.png)
tiếp tục là icmp và 2 ip quen thuộc
```
nguyen@nqghuy:~/CTF/forenshits$ tshark -r challenge.pcapng -Y "icmp.type == 8" -T fields -e data.data
624446755a31383d624446755a31383d624446755a31383d624446755a31383d624446755a31383d
101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637
4d545666597a413d4d545666597a413d4d545666597a413d4d545666597a413d4d545666597a413d
101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637
62573077626c383d62573077626c383d62573077626c383d62573077626c383d62573077626c383d
101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637
```
![alt text](/assets/img/posts/Data_Stolen/image-5.png)
Mảnh flag thứ 2

|FLAG: VSL{n3tw0rk_tunn3l1ng_15_c0mm0n_4tt4ck_t3chn1qu3}
