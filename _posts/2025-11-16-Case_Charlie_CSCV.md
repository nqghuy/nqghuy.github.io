---
title: "CSCV - Case Charlie (Hard)"
date: 2025-11-16 12:00:00 +0700
categories: [CTF, Digital Forensics]
tags: [forensics, disk-imaging, cscv]
image:
    path: ../assets/img/posts/Case_Charlie/banner.png
    alt: Case Charlie
---

Đây là 1 challenge ctf forensics trong cuộc thi sinh viên an ninh mạng. Bài này có số điểm là 400/500 với khoảng 7 đội giải được (mình không nhớ chính xác).
Đề cho ta một file vmdk. Yêu cầu của đề là trả lời hết 6 câu hỏi trong đề. Trả lời xong câu 6 sẽ có flag. Trước hết ta tiến hành mount file vmdk
```
sudo guestmount -a evidences.vmdk -i --ro /mnt/charlie/
```

ta đã có được file system
```
sudo ls /mnt/charlie
bin    dev   lib    libx32	mnt   root  snap      sys  var
boot   etc   lib32  lost+found	opt   run   srv       tmp
cdrom  home  lib64  media	proc  sbin  swap.img  usr
```

# Q1. What was the last time the suspect logged into the server? (UTC / 24 hours format)
Format: YYYY-MM-DD HH:MM:SS
```
sudo tree /mnt/charlie/var/log
/mnt/charlie/var/log
├── alternatives.log
├── apt
│   ├── eipp.log.xz
│   ├── history.log
│   └── term.log
├── audit
│   └── audit.log
├── bootstrap.log
├── btmp
├── cloud-init.log
├── cloud-init-output.log
├── dist-upgrade
├── dpkg.log
├── faillog
├── installer
│   ├── autoinstall-user-data
│   ├── block
│   │   ├── discover.log
│   │   └── probe-data.json
│   ├── casper-md5check.json
│   ├── cloud-init.log
│   ├── cloud-init-output.log
│   ├── curtin-install
│   │   ├── subiquity-curthooks.conf
│   │   ├── subiquity-curtin-apt.conf
│   │   ├── subiquity-extract.conf
│   │   ├── subiquity-initial.conf
│   │   └── subiquity-partitioning.conf
│   ├── curtin-install.log
│   ├── device-map.json
│   ├── installer-journal.txt
│   ├── media-info
│   ├── subiquity-client-debug.log -> subiquity-client-debug.log.2013
│   ├── subiquity-client-debug.log.2013
│   ├── subiquity-client-info.log -> subiquity-client-info.log.2013
│   ├── subiquity-client-info.log.2013
│   ├── subiquity-server-debug.log -> subiquity-server-debug.log.2037
│   ├── subiquity-server-debug.log.2037
│   ├── subiquity-server-info.log -> subiquity-server-info.log.2037
│   └── subiquity-server-info.log.2037
├── journal
│   └── 3f430965a019473c8245e89118d5a257
│       ├── system@f9d81d39b6ee4ba19579467382673abb-0000000000000001-0006420e14a4d3c3.journal
│       ├── system.journal
│       ├── user-1000@49d42328ba2f49f5ad23a4aac750b127-00000000000007e9-0006420e165f3c38.journal
│       └── user-1000.journal
├── lastlog
├── nginx
│   ├── access.log
│   └── error.log
├── private
├── unattended-upgrades
│   ├── unattended-upgrades-dpkg.log
│   ├── unattended-upgrades.log
│   └── unattended-upgrades-shutdown.log
└── wtmp
```
Trong thư mục có rất nhiều file log. 
```
nqghuy@nqghuy ~/C/f/c/c/forensics-Case_Charlie-f0f1f0e74a82270c9374bf0a9facd097> sudo utmpdump /mnt/charlie/var/log/wtmp | tail -n 10
Utmp dump of /mnt/charlie/var/log/wtmp
[2] [00000] [~~  ] [reboot  ] [~           ] [5.15.0-161-generic  ] [0.0.0.0        ] [2025-11-08T03:38:00,940732+00:00]
[1] [00053] [~~  ] [runlevel] [~           ] [5.15.0-161-generic  ] [0.0.0.0        ] [2025-11-08T03:38:07,513976+00:00]
[5] [00818] [tty1] [        ] [tty1        ] [                    ] [0.0.0.0        ] [2025-11-08T03:38:07,911440+00:00]
[6] [00818] [tty1] [LOGIN   ] [tty1        ] [                    ] [0.0.0.0        ] [2025-11-08T03:38:07,911440+00:00]
[7] [01408] [ts/0] [ubuntu  ] [pts/0       ] [192.168.237.1       ] [192.168.237.1  ] [2025-11-08T03:42:18,235666+00:00]
[7] [01454] [ts/1] [ubuntu  ] [pts/1       ] [tmux(1454).%0       ] [0.0.0.0        ] [2025-11-08T03:45:49,122724+00:00]
[7] [01454] [ts/2] [ubuntu  ] [pts/2       ] [tmux(1454).%1       ] [0.0.0.0        ] [2025-11-08T03:55:08,807043+00:00]
[8] [01454] [ts/2] [ubuntu  ] [pts/2       ] [                    ] [0.0.0.0        ] [2025-11-08T04:01:25,922202+00:00]
[7] [18760] [ts/2] [ubuntu  ] [pts/2       ] [192.168.237.1       ] [192.168.237.1  ] [2025-11-08T04:32:56,723780+00:00]
[8] [18760] [    ] [        ] [pts/2       ] [                    ] [0.0.0.0        ] [2025-11-08T04:37:41,998998+00:00]
```
file wtmp "is a binary file that records a historical log of all user logins, logouts, and system events like shutdowns and reboots". Lệnh `utmpdump` giúp đọc file này. ta thấy được 2025-11-08T04:32:56, có địa chỉ ip lan đăng nhập lần cuối cùng. Kiểm tra các file khác. File journal lưu log log hệ điều hành (kernel messages), log dịch vụ systemd (sshd, NetworkManager…), log ứng dụng,... Một số file journal hay audit.log (lưu log về bảo mật) có lưu thời gian sau (4:35,...) nhưng trong wtmp chỉ ghi nhận 4:32 nên đáp án là `2025-11-08 04:32:56`

# Q2: The suspect used a chat application to communicate. What is the name of this application?
```
nqghuy@nqghuy ~/C/f/c/c/forensics-Case_Charlie-f0f1f0e74a82270c9374bf0a9facd097 [2]> sudo ls /mnt/charlie/home/ubuntu
get-docker.sh  irclogs	lab  msfinstall  snap
nqghuy@nqghuy ~/C/f/c/c/forensics-Case_Charlie-f0f1f0e74a82270c9374bf0a9facd097> sudo ls /mnt/charlie/home/ubuntu/irclogs
liberachat  liberachat2  liberachat3
```
Hỏi gpt, ta ra được đó là log của irssi
# Q3 Identify the usernames (handles) of the suspect and their contact in the chat application. (Case Sensitive)
Đọc các file log bằng lệnh find + cat
```
nqghuy@nqghuy ~/C/f/c/c/forensics-Case_Charlie-f0f1f0e74a82270c9374bf0a9facd097> sudo find /mnt/charlie/home/ubuntu/irclogs -iname "*log" -exec cat {} \;
--- Log opened Fri Nov 07 12:56:16 2025
12:56 -!- Irssi: Starting query in liberachat with the0nlymak3r1338
12:56 <the0nlymak3r1338> yo
12:56 <the0nlymak3r1338> hello
12:56 <s3v3n_wOndEr113> yooo
12:56 <s3v3n_wOndEr113> i see your msg
12:56 <s3v3n_wOndEr113> O_O
12:56 <the0nlymak3r1338> okay
12:56 <the0nlymak3r1338> good to see u mate
12:56 <the0nlymak3r1338> 😊
12:57 <the0nlymak3r1338> is everything good?
12:57 <s3v3n_wOndEr113> good in what?
12:57 <the0nlymak3r1338> your new server and setup
12:57 <s3v3n_wOndEr113> yeah sure
12:57 <s3v3n_wOndEr113> its working fine for now
12:57 <s3v3n_wOndEr113> im configuring some tools
12:57 <the0nlymak3r1338> thats good to hear
12:57 <the0nlymak3r1338> imma sent you the image soon
12:58 <s3v3n_wOndEr113> okay
12:59 <the0nlymak3r1338> have u seen this https://t.co/I5W6VdUgSy
13:00 <s3v3n_wOndEr113> nope
```
kết quả là `s3v3n_wOndEr113, the0nlymak3r1338`

# Q4: What was the last time the suspect sent a message to their contact? (UTC / 24 hours format)
```
04:34 <the0nlymak3r1338> luckily, you have your own server
04:35 <s3v3n_wOndEr113> O_O
04:36 <s3v3n_wOndEr113> oh shit
04:36 <the0nlymak3r1338> what
--- Log opened Sat Nov 08 04:01:03 2025
....
--- Log opened Sat Nov 08 04:32:58 2025
--- Log opened Sat Nov 08 04:00:08 2025
04:00 -!- Irssi: Starting query in liberachat3 with the0nlymak3r1338
04:00 <s3v3n_wO3dEr113> .
04:00 -!- Irssi: Closing query with the0nlymak3r1338
--- Log closed Sat Nov 08 04:00:20 2025
--- Log opened Sat Nov 08 04:00:03 2025
--- Log closed Sat Nov 08 04:00:31 2025
--- Log opened Sat Nov 08 03:58:50 2025
03:58 -!- Irssi: Starting query in liberachat2 with the0nlymak3r1338
03:58 <s3v3n_wO2dEr113> yo
03:58 -!- Irssi: Closing query with the0nlymak3r1338
--- Log closed Sat Nov 08 03:58:56 2025
--- Log opened Sat Nov 08 03:59:29 2025
03:59 -!- Irssi: Starting query in liberachat2 with the0nlymak3r1338
03:59 <s3v3n_wO2dEr113> .
03:59 <s3v3n_wO2dEr113> .
03:59 -!- Irssi: Closing query with the0nlymak3r1338
--- Log closed Sat Nov 08 03:59:43 2025
...
--- Log opened Sat Nov 08 04:00:49 2025
--- Log closed Sat Nov 08 04:00:54 2025
```
Vậy đáp án là `2025-11-08 04:36`
# Q5 What command did the suspect use to overwrite the current user's .bash_history file to cover their tracks?
Sử dụng grep
```
nqghuy@nqghuy ~/C/f/c/c/forensics-Case_Charlie-f0f1f0e74a82270c9374bf0a9facd097> sudo grep -R "bash_history" /mnt/charlie/var/log/
grep: /mnt/charlie/var/log/journal/3f430965a019473c8245e89118d5a257/system.journal: binary file matches
grep: /mnt/charlie/var/log/journal/3f430965a019473c8245e89118d5a257/user-1000.journal: binary file matches
```
ta thấy 2 file journal ghi lại
```
nqghuy@nqghuy ~/C/f/c/c/forensics-Case_Charlie-f0f1f0e74a82270c9374bf0a9facd097> sudo find /mnt/charlie/var/log/journal/ -type f -name "*.journal" -exec journalctl --file={} \;| grep bash_history
Nov 08 11:37:34 vmi-59f23d81a3fa0e sudo[19288]:   ubuntu : TTY=pts/2 ; PWD=/home/ubuntu/lab ; USER=root ; COMMAND=/usr/bin/shred -vfz /root/.bash_history
Nov 08 11:37:34 vmi-59f23d81a3fa0e sudo[19291]:   ubuntu : TTY=pts/2 ; PWD=/home/ubuntu/lab ; USER=root ; COMMAND=/usr/bin/rm -f /root/.bash_history
Nov 08 11:37:34 vmi-59f23d81a3fa0e sudo[19294]:   ubuntu : TTY=pts/2 ; PWD=/home/ubuntu/lab ; USER=root ; COMMAND=/usr/bin/shred -vfz /home/ubuntu/.bash_history
Nov 08 11:37:34 vmi-59f23d81a3fa0e sudo[19297]:   ubuntu : TTY=pts/2 ; PWD=/home/ubuntu/lab ; USER=root ; COMMAND=/usr/bin/rm -f /home/ubuntu/.bash_history
```
Đáp án là `sudo shred -vfz /root/.bash_history` do nó thực thi dưới root. Lệnh rm -rf chỉ đơn giản là xóa không phải ovewrite   

# Q6 The suspect accidentally left behind an email address. What is the email address?
Đây là câu khó nhất trong bài và tốn rất nhiều thời gian của mình. Dù mình đã đi đúng hướng trước khi hint được đưa ra. Đầu tiên mình thử grep email
![alt text](../assets/img/posts/Case_Charlie/email.png)
Rất nhiều email, chủ yếu là các tác giả github. Mình có thử nhiều các khác và đọc log chat của hung thủ
```
04:02 <s3v3n_wOndEr113> hi
04:02 <the0nlymak3r1338> yo i see you now
04:02 <the0nlymak3r1338> what happened
04:02 <s3v3n_wOndEr113> my nickname messed up
04:02 <the0nlymak3r1338> lol
04:03 <the0nlymak3r1338> anyway
04:03 <the0nlymak3r1338> ive built an image
04:03 <the0nlymak3r1338> somegroup5803945/jkfhskdf2314
04:03 <s3v3n_wOndEr113> cool bro
04:03 <s3v3n_wOndEr113> let me try it
04:03 <the0nlymak3r1338> yeah it just testing
04:03 <the0nlymak3r1338> use 'testing' to pull it
04:03 <s3v3n_wOndEr113> okay
04:04 <s3v3n_wOndEr113> old cred?
04:04 <the0nlymak3r1338> yeah same old cred mate
04:04 <the0nlymak3r1338> ^_^
04:04 <s3v3n_wOndEr113> i see
```
1 người có build một image. Người kia xác nhận sử dụng cred cũ để pull về.
![alt text](../assets/img/posts/Case_Charlie/docker_auth.png)

```
nqghuy@nqghuy ~/C/f/c/c/forensics-Case_Charlie-f0f1f0e74a82270c9374bf0a9facd097> sudo cat /mnt/charlie/home/ubuntu/.docker/config.json
{
	"auths": {
		"registry.gitlab.com": {
			"auth": "YXNqZGtodWZoODMyOmdscGF0LXh3Z2hRYkRUc0piczFCMk11Ylhfekc4Nk1RcDFPbWx4T0hWekN3LjAxLjEyMHl2dHAyZg=="
		}
	}
}⏎                                                                                                                                                                           nqghuy@nqghuy ~/C/f/c/c/forensics-Case_Charlie-f0f1f0e74a82270c9374bf0a9facd097> echo YXNqZGtodWZoODMyOmdscGF0LXh3Z2hRYkRUc0piczFCMk11Ylhfekc4Nk1RcDFPbWx4T0hWekN3LjAxLjEyMHl2dHAyZg== | base64 -d
asjdkhufh832:glpat-xwghQbDTsJbs1B2MubX_zG86MQp1OmlxOHVzCw.01.120yvtp2f
```
Ta đã có auth của gitlab. Đăng nhập vào 
```
                                                                                 docker login registry.gitlab.com

Removing login credentials for registry.gitlab.com
Username: asjdkhufh832
Password: 
WARNING! Your password will be stored unencrypted in /home/nqghuy/.docker/config.json.
Configure a credential helper to remove this warning. See
https://docs.docker.com/engine/reference/commandline/login/#credential-stores

Login Succeeded
```
Theo log chat, ta có tên dự án là somegroup5803945/jkfhskdf2314. Tiến hành clone, dự án theo `git clone https://username:password@gitlab.com/somegroup5803945/jkfhskdf2314`
```
nqghuy@nqghuy ~/C/f/c/c/f/test> git clone https://asjdkhufh832:glpat-3uxiCwpsVnrRJxzVFwfhWm86MQp1OmlxOHVzCw.01.120qf0pou@gitlab.com/somegroup5803945/jkfhskdf2314.git
Cloning into 'jkfhskdf2314'...
remote: Enumerating objects: 8, done.
remote: Counting objects: 100% (8/8), done.
remote: Compressing objects: 100% (7/7), done.
remote: Total 8 (delta 1), reused 0 (delta 0), pack-reused 0 (from 0)
Receiving objects: 100% (8/8), 8.83 KiB | 8.83 MiB/s, done.
Resolving deltas: 100% (1/1), done.
```
sử dụng git log để xem commit và tên email (mình không thạo git lắm nên không không biết xem commit có thể xem được email)
```
nqghuy@nqghuy ~/C/f/c/c/f/t/jkfhskdf2314 (main)> git log --all --decorate --graph
* commit c5d658cf17134c548bb161a0ea74faef94cea9b9 (HEAD -> main, origin/main, origin/HEAD)
| Author: jkahsd <phuchungh96@gmail.com>
| Date:   Fri Nov 7 19:08:43 2025 +0700
| 
|     add src code
| 
* commit 56a1f5fa74d2d6625b54f774f5343c3e37755ec9
  Author: Phuc Hung Huynh <phuchungh96@gmail.com>
  Date:   Fri Nov 7 12:03:43 2025 +0000
  
      Initial commit
```

Như vậy email của hung thủ là `phuchungh96@gmail.com`

| FLAG: cscv{5p4wn3r_15_4w350m3_4nd_53cur3}