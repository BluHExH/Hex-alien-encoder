# Hex-alien-encoder
Education perpos only i am not responsible.... 





![My image](https://raw.githubusercontent.com/BluHExH/Profile/refs/heads/main/hex.gif)


<p align="center"><img src="https://img.shields.io/badge/I Am %20A BANGLADESHI- PROGRAMMER-green?colorA=%23ff0000&colorB=%23017e40&style=flat-square">
 

<!-- Animated HEX Banner -->
<p align="center">
  <img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=30&pause=1000&color=39FF14&center=true&vCenter=true&width=600&lines=Hacker+Hex;Full+Stack+Developer;Cybersecurity+Enthusiast;Open+Source+Contributor" alt="Typing SVG" />
</p>

<!-- Gradient HEX Name -->
<h1 align="center">
  <img src="https://svg-banners.vercel.app/api?type=glitch&text1=H%20E%20X&width=800&height=200" alt="HEX Banner" />



# ⚡ HEX Alien Encoder Pro - Ultimate File Obfuscation Tool

### 🔒 Developed by: Cyber 17 Official  
### 🧠 Version: HEX-ALIEN-PRO-V2  
### 🧩 File: `elitehex.py`

---

## 🚀 Overview

**HEX Alien Encoder Pro** হল এক উন্নত স্তরের **ফাইল এনকোডিং ও অবফুসকেশন টুল**, যা যেকোনো স্ক্রিপ্ট, কোড, বা টেক্সট ফাইলকে “Alien Symbol Code” এ রূপান্তর করে।  
এটা মূলত নিরাপদভাবে কোড বা ডেটা শেয়ার ও সংরক্ষণের জন্য ব্যবহৃত হয় — কেউ সহজে পড়ে বা কপি করতে পারবে না।

🛡️ **মূল উদ্দেশ্য:**  
- ফাইল এনক্রিপ্ট ও হিউম্যান-রিডেবল ফরম্যাটে লুকানো  
- ডিকোড না করা পর্যন্ত আসল কনটেন্ট দেখা যাবে না  
- কোনো ফাইল স্বয়ংক্রিয়ভাবে রান হয় না (Fully Safe Mode)

---

## ✨ Key Features

✅ Multi-file encoding support  
✅ Random alien symbol mapping  
✅ SHA-256 signature verification (tamper detection)  
✅ Secure passphrase encryption  
✅ File integrity check  
✅ Fancy animated CLI UI  
✅ Safe decoding – never auto-executes any code  
✅ Cross-platform (Windows / Linux / Termux)  

---

## ⚙️ Installation

**Requirements:**  
- Python 3.8 or higher  
- No extra modules required (pure Python)

**Run Command (Termux/Linux/Windows):**
```bash
python elitehex.py
```

---

## 🔥 Usage

### 🔹 Encode One or More Files

```bash
python elitehex.py encode script.py output.aln --passphrase mysecret
```

➡️ Multiple files encode করতে:
```bash
python elitehex.py encode file1.py file2.txt output.aln --passphrase mysecret --randomize
```

**Parameters Explained:**
- `encode` → এনকোড মোড সক্রিয় করে  
- `--passphrase` → নিরাপত্তার জন্য গোপন কী  
- `--randomize` → এলোমেলো symbol mapping ব্যবহার করবে (আরও নিরাপদ)  
- `--seed` → নির্দিষ্ট seed দিলে reproducible randomization হবে  

---

### 🔹 Decode an Encoded File

```bash
python elitehex.py decode output.aln --passphrase mysecret
```

➡️ ডিকোড করা ফাইল সংরক্ষণ করতে:
```bash
python elitehex.py decode output.aln --passphrase mysecret --save restored.py
```

---

### 🔹 List Files Inside Encoded Package

```bash
python elitehex.py list output.aln
```
এটা ডিকোড না করেই package-এর ভিতরের ফাইল ও metadata দেখাবে।

---

### 🔹 Show Tool Info & Symbol Stats

```bash
python elitehex.py info
```

এটা symbol pool, version, features এবং random mapping সম্পর্কিত তথ্য দেখাবে।

---

## 🧠 Internal Working Explained

### 🧩 1. Encoding Process
1. ইনপুট ফাইলগুলোকে **Base64 encode** করা হয়।  
2. প্রতিটি ফাইলের নাম, সাইজ, timestamp সহ **JSON bundle** তৈরি হয়।  
3. SHA-256 দিয়ে signature তৈরি হয় (passphrase + encoded content)।  
4. Base64 টেক্সটকে **Alien Symbol Mapping** দিয়ে পরিবর্তন করা হয়।  
5. সবশেষে `.aln` ফাইলে লেখা হয়, যার হেডারে থাকে map ও randomization তথ্য।

### 🧩 2. Decoding Process
1. Header পড়ে symbol map পুনর্গঠন করা হয়।  
2. Alien symbols → Base64 → Original JSON bundle এ রূপান্তর করা হয়।  
3. SHA-256 signature verify করে দেখা হয় ফাইলটি টেম্পারড কিনা।  
4. Preview তে সব ফাইল, সাইজ, কন্টেন্ট দেখা যায়।  
5. চাইলে `--save` দিয়ে আসল ফাইল আলাদা করে সেভ করা যায়।

---

## 📂 Example Output

Encoding শেষে টার্মিনালে এমন দেখা যাবে:

```
🚀 Starting Elite Encoding Process...
✅ ENCODING COMPLETED SUCCESSFULLY!
📁 Output File: encoded.aln
📊 Files Encoded: 2
💾 Total Size: 12,489 bytes
🔐 Signature: 2fa8bc94109f7c82...
🎯 Symbol Randomization: ENABLED
```

Decoding এ এমন দেখা যাবে:
```
🎉 DECODE SUCCESSFUL - PACKAGE PREVIEW
📦 Package Metadata:
   Version: HEX-ALIEN-PRO-V2
   Total Files: 2
   Total Size: 12,489 bytes
📄 script.py (Preview):
   print("Hello Alien World!")
```

---

## ⚡ Command Summary

| Command | Description |
|----------|--------------|
| `encode` | Encode one or multiple files |
| `decode` | Decode an encoded package |
| `list`   | Show files inside a package |
| `info`   | Display tool info and symbol stats |

---

## 🧰 Technical Specifications

| Category | Details |
|-----------|----------|
| Language | Python 3 |
| Encryption | SHA-256 Signature |
| Symbol Pool | 200+ Alien Unicode Symbols |
| Mapping | Randomized or Static |
| Output Format | `.aln` |
| Compatibility | Windows, Linux, Termux |
| Safety | No code execution during decode |

---

## ⚠️ Security Notes
- Passphrase ভুল দিলে ফাইল খুলবে না  
- Signature mismatch মানে ফাইল টেম্পার হয়েছে  
- Decode safe mode – কোনো ফাইল execute হয় না  
- Alien symbols শুধুমাত্র এই টুল দিয়েই পড়া সম্ভব  

---

## 🧾 License
This project is for **educational and research purposes only.**  
Unauthorized misuse or malicious redistribution is strictly prohibited.

---

## 👑 Credits
**Developer:** Hacker Hex (Cyber 17 Official)  
**Tool Name:** HEX Alien Encoder Pro  
**Version:** V2 (Elite Edition)  
**Created:** 2025  

---

🧠 *"Protect your code like an alien encrypts its secrets."* 👽
