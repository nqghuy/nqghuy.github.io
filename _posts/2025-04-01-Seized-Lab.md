---
title: "Seized Lab - Linux Rootkit Analysis"
date: 2025-07-04 12:00:00 +0700
categories: [CTF, Forensics]
tags: [linux, rootkit, volatility, memory-forensics, syscall-hooking]
image:
  path: /assets/img/posts/Seized-Lab/banner.png
  alt: Seized Lab
---

## Giới thiệu

**Difficulty**: Medium  
**Category**: Endpoint  
**Tools**: Volatility 2

Bài lab phân tích rootkit trên hệ thống Linux CentOS bị compromised.

## Q1: What is the CentOS version installed on the machine?

Chạy plugin `linux_banner` ta được 

```jsx
Linux version 3.10.0-1062.el7.x86_64 (mockbuild@kbuilder.bsys.centos.org) (gcc version 4.8.5 20150623 (Red Hat 4.8.5-36) (GCC) ) #1 SMP Wed Aug 7 18:08:02 UTC 2019
```

Click vào link

[https://github.com/gunh0/linux-kernel](https://github.com/gunh0/linux-kernel)

![image.png](/assets/img/posts/Seized-Lab/image.png)

Ta thấy nhân 3.10.0-1062 là của bản `7.7.1908`

Hoặc tra trên [https://en.wikipedia.org/wiki/CentOS#CentOS_version_7](https://en.wikipedia.org/wiki/CentOS#CentOS_version_7)

![image.png](/assets/img/posts/Seized-Lab/image%201.png)

## Q2: There is a command containing a strange message in the bash history. Will you be able to read it?

Attacker thường cố gắng giấu đi `bash_history` nhưng plugin `linux_bash` có thể recover

![image.png](/assets/img/posts/Seized-Lab/image%202.png)

## Q3: What is the PID of the suspicious process?

Đầu tiên ta chạy lệnh plugin `linux_pstree`

```jsx
.ncat                2854
..bash               2876
...python            2886
....bash             2887
.....vim             3196
.abrt-dbus           3271
```

Ta thấy tiến trình ncat có các tiến trình con bất thường.

Hoặc ta có thể xem các kết nối ngoài bằng plugin `linux_netstat`

## Q4: The attacker downloaded a backdoor to gain persistence. What is the hidden message in this backdoor?

Từ Q2, ta có được 2 link github

```jsx
https://github.com/tw0phi/PythonBackup
```

Trong đó link này có 0 star

![image.png](/assets/img/posts/Seized-Lab/image%203.png)

File `http://snapshot.py` có thanh ngang dài bất thường

![image.png](/assets/img/posts/Seized-Lab/image%204.png)

Lệnh này sẽ tải về file lệnh và thực thi ngay. Điều này giúp thực thi mã độc và không để lại dấu vết gì hết trên đĩa

```jsx
┌──(nqghuy㉿kali)-[/mnt/…/CTF/forensics/92-Seized/temp_extract_dir]
└─$ echo c2hrQ1RGe3RoNHRfdzRzXzRfZHVtYl9iNGNrZDAwcl84NjAzM2MxOWUzZjM5MzE1YzAwZGNhfQo= | base64 -d
shkCTF{th4t_w4s_4_dumb_b4ckd00r_86033c19e3f39315c00dca}
```

## Q5: What are the attacker's IP address and the local port on the targeted machine?

Kiểm tra với plugin `linux_netstat`

```jsx
TCP      192.168.49.135  :12345 192.168.49.1    :44122 ESTABLISHED                  ncat/2854
TCP      192.168.49.135  :12345 192.168.49.1    :44122 ESTABLISHED                  bash/2876
TCP      192.168.49.135  :12345 192.168.49.1    :44122 ESTABLISHED                python/2886
TCP      192.168.49.135  :12345 192.168.49.1    :44122 ESTABLISHED                  bash/2887
TCP      192.168.49.135  :12345 192.168.49.1    :44122 ESTABLISHED                   vim/3196
```

→ 192.168.49.1:12345

## Q6: What is the first command that the attacker executed?

```jsx
linux_psaux                - Gathers processes along with full command line and start time
```

Ta sử dụng plugin `linux_psaux`

**`linux_psaux`** đọc từ bảng process (`task_struct`) của kernel → nó cho thấy **các process còn đang chạy** ở thời điểm memory dump.

- Ví dụ: khi bạn chạy `git clone`, quá trình đó chỉ tồn tại vài giây. Lúc chụp memory nó đã **kết thúc**, nên không còn thấy trong `linux_psaux`.

**`linux_bash`** đọc từ **bộ nhớ của tiến trình bash** → nó lưu lại **lịch sử các lệnh đã gõ** trong session bash, kể cả lệnh đã chạy xong từ trước.

- Vì vậy nó vẫn thấy `git clone https://github.com/tw0phi/PythonBackup`, `unzip`, `sudo python PythonBackup.py`,… dù các process này không còn chạy.

![image.png](/assets/img/posts/Seized-Lab/image%205.png)

- **Attacker tạo backdoor với Ncat**
    - Trong `linux_psaux` thấy lệnh:
        
        ```bash
        ncat -lvp 12345 -e /bin/bash
        ```
        
        Nghĩa là máy bị tấn công mở cổng **12345** và bất kỳ ai kết nối tới sẽ nhận được một **Bash shell**.
        
- **Hạn chế của shell từ Ncat**
    - Shell này là "dumb shell": không có tính năng như terminal thật (**không có history, tab completion, Ctrl+C**, v.v.).
    - Khó dùng nếu attacker muốn thao tác lâu dài.
- **Attacker nâng cấp shell với Python**
    - Tiếp theo, attacker chạy:
        
        ```python
        python -c 'import pty; pty.spawn("/bin/bash")'
        ```
        
        Đây là kỹ thuật **upgrade shell**: dùng Python để tạo một **pseudo-terminal (PTY)**, biến shell đơn giản thành một **interactive TTY shell** gần giống như khi SSH vào máy.

## Q7: After changing the root password, we found that the attacker still has access. Can you find out how?

Nếu attacker đã thêm public key của họ vào file `~/.ssh/authorized_keys` trên máy nạn nhân, thì sau đó họ có thể truy cập lại máy bất cứ lúc nào như sau:

1. **Từ máy của attacker**:
    - Họ giữ **private key** tương ứng với public key đã cài vào server.
    - Họ chỉ cần dùng lệnh SSH:
        
        ```bash
        ssh -i attacker_key.pem user@victim_ip
        ```
        
        hoặc thậm chí chỉ cần `ssh user@victim_ip` nếu private key đã được load vào ssh-agent.
        
2. **Server không yêu cầu mật khẩu**:
    - Vì khi SSH server thấy public key trong `~/.ssh/authorized_keys`, nó xác thực bằng private key mà attacker giữ.
    - Password authentication bị **bỏ qua hoàn toàn**.
3. **Hậu quả**:
    - Dù bạn đã đổi mật khẩu tài khoản, attacker vẫn đăng nhập bình thường.
    - Họ có toàn quyền trên server, có thể cài thêm backdoor, lấy dữ liệu, hoặc leo thang quyền root.

```jsx
3196   0      0      vim /etc/rc.local
```

Ở plugin `ps_aux`, ta có thấy tiến trình trên

Tiến hành dump tiến trình

```bash
vol2 -f dump.mem --profile=LinuxCentos7_3_10_1062x64 linux_dump_map --pid 3196 -D 3196/
```

![image.png](/assets/img/posts/Seized-Lab/image%206.png)

→ `shkCTF{rc.l0c4l_1s_funny_be2472cfaeed467ec9cab5b5a38e5fa0}`.

## Q8: What is the name of the rootkit that the attacker used?

- **Rootkit là gì?**
    
    Là một loại malware đặc biệt nguy hiểm, chạy ở **mức kernel** (lõi hệ điều hành). Nó cho phép attacker kiểm soát hệ thống rất sâu mà gần như không bị phát hiện.
    
- **Tại sao khó phát hiện?**
    
    Rootkit có thể **ẩn đi chính nó** và các hoạt động độc hại: giấu process, file, network connection… khỏi các công cụ bảo mật bình thường (như `ps`, `ls`, antivirus).
    
- **Cách rootkit làm điều đó – syscall hooking:**
    - **System calls (syscalls)** là "cầu nối" giữa chương trình người dùng và kernel, ví dụ: mở file (`open`), liệt kê process (`getdents`), tạo kết nối mạng (`connect`).
    - Rootkit **chỉnh sửa bảng syscall**: thay vì gọi hàm hợp pháp của hệ điều hành, các lệnh sẽ bị **chuyển hướng** tới code của rootkit.
    - Nhờ đó, rootkit có thể **giả mạo kết quả**. Ví dụ:
        - Khi bạn chạy `ps` → nó trả về danh sách process nhưng **ẩn process của rootkit**.
        - Khi bạn liệt kê file → nó **ẩn các file backdoor**.
- **Hệ quả:**
    - Attacker có quyền kiểm soát sâu mà hầu như không bị phát hiện.
    - Rất khó loại bỏ vì rootkit đã "chen" vào phần lõi của hệ điều hành.

```jsx
linux_check_syscall        - Checks if the system call table has been altered
```

Sử dụng plugin này

```jsx
64bit         88                          0xffffffffc0a12470 HOOKED: sysemptyrect/syscall_callback 
```

**`HOOKED: sysemptyrect/syscall_callback`** – Volatility phát hiện rằng syscall này đã bị thay đổi để gọi một hàm **`syscall_callback`** (do rootkit cung cấp), thay vì hàm gốc.

Nếu phát hiện lệch khỏi code gốc của kernel, nó đánh dấu là **"HOOKED"**.

## Q9: The rootkit uses crc65 encryption. What is the key?

```bash
┌──(nqghuy㉿kali)-[/mnt/…/CTF/forensics/92-Seized/temp_extract_dir]
└─$ strings 2887/* | grep "crc65" # tiến trình bash
ysemptyrect.ko crc65_key="1337tibbartibb
```

Hoặc sử dụng 

```jsx
linux_lsmod                - Gather loaded kernel modules
```

Với option -P

![image.png](/assets/img/posts/Seized-Lab/image%207.png)

```jsx
ffffffffc0a14020 sysemptyrect 12904
        crc65_key=1337tibbartibbar
```

Plugin **`linux_dmesg`** trong Volatility 2 dùng để **trích xuất bộ nhớ đệm của `dmesg`** từ memory dump.

- Rootkit thường phải **nạp kernel module** (LKM), và việc nạp này thường để lại log trong `dmesg`.
- Có thể thấy các thông báo lỗi hoặc bất thường (ví dụ: syscall bị hook, module không hợp lệ).

Sử dụng plugin này

```jsx
[172141977023.172] sysemptyrect: loading out-of-tree module taints kernel.
[172142219596.172] sysemptyrect: module verification failed: signature and/or required key missing - tainting kernel
[172143083725.172] CRC65: rdy to encrypt stuff!
[300788224353.300] ------------[ cut here ]------------
[300788229798.300] WARNING: CPU: 0 PID: 3217 at mm/vmalloc.c:1484 __vunmap+0xf2/0x100
[300788230901.300] Trying to vfree() bad address (6852565977646e55)
[300788231652.300] Modules linked in: sysemptyrect(OE) tcp_lp nls_utf8 isofs rfcomm fuse xt_CHECKSUM iptable_mangle ipt_MASQUERADE nf_nat_masquerade_ipv4 iptable_nat nf_nat_ipv4 nf_nat nf_conntrack_ipv4 nf_defrag_ipv4 xt_conntrack nf_conntrack ipt_REJECT nf_reject_ipv4 tun bridge stp llc ebtable_filter ebtables devlink ip6table_filter ip6_tables iptable_filter vmw_vsock_vmci_transport vsock bnep sunrpc snd_seq_midi snd_seq_midi_event iosf_mbi crc32_pclmul ghash_clmulni_intel ppdev snd_ens1371 btusb snd_rawmidi aesni_intel snd_ac97_codec btrtl btbcm ac97_bus btintel vmw_balloon lrw snd_seq gf128mul bluetooth glue_helper ablk_helper cryptd snd_seq_device snd_pcm joydev pcspkr snd_timer rfkill snd sg soundcore vmw_vmci i2c_piix4 parport_pc parport pcc_cpufreq ip_tables xfs libcrc32c sr_mod cdrom ata_generic
[300788258993.300]  pata_acpi sd_mod crc_t10dif crct10dif_generic vmwgfx drm_kms_helper syscopyarea sysfillrect sysimgblt fb_sys_fops ttm crct10dif_pclmul crct10dif_common nfit crc32c_intel drm libnvdimm ata_piix serio_raw mptspi scsi_transport_spi libata e1000 mptscsih mptbase drm_panel_orientation_quirks dm_mirror dm_region_hash dm_log dm_mod
[300788271159.300] CPU: 0 PID: 3217 Comm: git Tainted: G           OE  ------------   3.10.0-1062.el7.x86_64 #1
[300788272108.300] Hardware name: VMware, Inc. VMware Virtual Platform/440BX Desktop Reference Platform, BIOS 6.00 07/29/2019
[300788273058.300] Call Trace:
[300788276964.300]  [<ffffffffa8579262>] dump_stack+0x19/0x1b
[300788279532.300]  [<ffffffffa7e9a878>] __warn+0xd8/0x100
[300788281233.300]  [<ffffffffa7e9a8ff>] warn_slowpath_fmt+0x5f/0x80
[300788282718.300]  [<ffffffffa80023f2>] __vunmap+0xf2/0x100
[300788283996.300]  [<ffffffffa8002476>] vfree+0x36/0x70
[300788286116.300]  [<ffffffffc0a1263d>] syscall_callback+0x1cd/0x310 [sysemptyrect]
[300788290150.300]  [<ffffffffa858bede>] system_call_fastpath+0x25/0x2a
[300788291335.300] ---[ end trace 518bb9ed1eeeedb8 ]---
```

Ta thấy có module bị mã hóa crc65

![image.png](/assets/img/posts/Seized-Lab/image%208.png)
