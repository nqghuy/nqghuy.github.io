---
title: "Docker Layer - Container Forensics Analysis"
date: 2025-07-04 12:00:00 +0700
categories: [CTF, Forensics]
tags: [docker, containers, layer-analysis, image-forensics, manifest, openssl]
image:
  path: /assets/img/posts/NLTM/banner.png
  alt: rootme
---

## Giới thiệu

**Difficulty**: Easy  
**Category**: Endpoint

Bài lab phân tích Docker image layers để tìm file bị ẩn và giải mã flag.

## Docker image và các layer

- **Docker image** là một gói chứa toàn bộ filesystem (OS, ứng dụng, file cần thiết) để chạy container.
- Một image được build theo từng **layer**:
    - Mỗi lệnh trong Dockerfile (`RUN`, `COPY`, `ADD`...) tạo ra một layer mới.
    - Các layer này được lưu dưới dạng file `.tar` riêng biệt.
    - Khi image chạy, Docker ghép tất cả các layer theo thứ tự.
- Nếu một file bị xóa trong layer cuối (`RUN rm /pass.txt`), nó sẽ không xuất hiện trong container đang chạy, nhưng vẫn tồn tại trong layer trước.

## File `manifest.json` và `repositories`

- Khi bạn export hoặc load một image (bằng `docker save` hay `docker load`), Docker tạo ra một bundle `.tar` chứa:
    - Các layer `.tar`
    - `manifest.json`: mô tả image (danh sách layer, cấu hình, tag, lệnh CMD mặc định...)
    - `repositories`: tên và tag của image.

File JSON bạn xem lúc nãy chính là phần `config`, trong đó có:

- `history`: liệt kê các lệnh được chạy khi build image.
- `rootfs.diff_ids`: ID các layer.

## `docker load`

- Dùng để import một image từ file `.tar` (đã được `docker save`).
- Khi load, Docker ghi nhận tất cả layer và thông tin từ `manifest.json`.

Do file pass.txt bị xóa ở layer cuối, ta chỉ cần extract layer đằng trước để tìm file này

```bash
┌──(nqghuy㉿kali)-[/mnt/e/CTF/forensics/ch29]
└─$ for f in *.tar; do
        tar -xvf "$f"
done
```

```bash
┌──(nqghuy㉿kali)-[/mnt/e/CTF/forensics/ch29]
└─$ ls
1bbd61a572ad5f5e2ac0f073465d10dc1c94a71359b0adfd2c105be4c1cb2507       lib
316bbb8c58be42c73eefeb8fc0fdc6abb99bf3d5686dd5145fc7bb2f32790229.tar   lib32
3309d6da2bd696689a815f55f18db3f173bc9b9a180e5616faf4927436cf199d.tar   lib64
4942a1abcbfa1c325b1d7ed93d3cf6020f555be706672308a4a4a6b6d631d2e7.tar   libx32
5bcc45940862d5b93517a60629b05c844df751c9187a293d982047f01615cb30       manifest.json
743c70a5f809c27d5c396f7ece611bc2d7c85186f9fdeb68f70986ec6e4d165f.tar   media
82ba49da0bd5d767f35d4ae9507d6c4552f74e10f29777a2a27c97778962476d       mnt
8d364403e7bf70d7f57e807803892edf7304760352a397983ecccb3e76ca39fa.tar   opt
8f0d75885373613641edc42db2a0007684a0e5de14c6f854e365c61f292f3b4d       pass.txt
b324f85f8104bfebd1ed873e90437c0235d7a43f025a047d5695fe461da717c6.json  proc
b58c5e8ccaba8886661ddd3b315989f5cf7839ea06bbe36547c6f49993b0d0aa.tar   repositories
bin                                                                    root
boot                                                                   run
ca7f60c6e2a66972abcc3147da47397d1c2edb80bddf0db8ef94770ed28c5e16       sbin
db04fe239ab708e4ab56ea0e5c1047449b7ea9e04df9db5b1b95d00c6980ff3f       srv
dev                                                                    sys
etc                                                                    temp
flag.enc                                                               tmp
home                                                                   usr
image2.tar                                                             var
image.tar
                                                                                                                
┌──(nqghuy㉿kali)-[/mnt/e/CTF/forensics/ch29]
└─$ cat pass.txt
d4428185a6202a1c5806d7cf4a0bb738a05c03573316fe18ba4eb5a21a1bc8ea 
```

```bash
┌──(nqghuy㉿kali)-[/mnt/e/CTF/forensics/ch29]
└─$ openssl enc -d -aes-256-cbc -iter 10 -pass pass:$(cat pass.txt) -in flag.enc -out flag.txt
                                                                                                                
┌──(nqghuy㉿kali)-[/mnt/e/CTF/forensics/ch29]
└─$ cat flag.txt
Well_D0ne_D0ckER_L@y3rs_Inspect0R
```

