# CyberShield - เครื่องมือรักษาความปลอดภัยไซเบอร์

> โปรเจค Portfolio ด้าน Cybersecurity ที่แสดงทักษะด้านความปลอดภัยเครือข่าย, การเข้ารหัสข้อมูล และ Ethical Hacking

## ภาพรวม

CyberShield เป็นชุดเครื่องมือรักษาความปลอดภัยไซเบอร์ที่สร้างด้วย Python แสดงความรู้จริงทางด้าน:

- **Network Security** - สแกนพอร์ต, สำรวจเครือข่าย
- **Cryptography** - เข้ารหัส, ถอดรหัส และแฮช
- **Password Security** - วิเคราะห์ความแรงรหัสผ่าน
- **Web Security** - ค้นหา subdomain และประเมินช่องโหว่
- **Packet Analysis** - ตรวจสอบและวิเคราะห์ทราฟิกเครือข่าย

## เครื่องมือที่มี

| เครื่องมือ | รายละเอียด | Tech Stack |
|-----------|------------|------------|
| Port Scanner | สแกนพอร์ตที่เปิดบนเป้าหมาย | Python, Socket |
| Packet Analyzer | จับและวิเคราะห์ทราฟิกเครือข่าย | Python, Scapy |
| Password Analyzer | ตรวจความแรงรหัสผ่าน | Python, zxcvbn |
| Encryption Suite | เข้ารหัส AES, RSA และ cipher อื่นๆ | Python, cryptography |
| Subdomain Scanner | ค้นหา subdomain ของโดเมน | Python, aiohttp |
| Hash Cracker | สาธิต rainbow table attack | Python, hashlib |

## วิธีติดตั้งและรัน

```bash
# Clone โปรเจค
git clone https://github.com/yourusername/cybershield.git
cd cybershield

# สร้าง virtual environment
python3 -m venv venv
source venv/bin/activate

# ติดตั้ง dependencies
pip install -r requirements.txt

# รัน dashboard
python dashboard.py
```

จากนั้นเปิดเบราว์เซอร์ไปที่ `http://127.0.0.1:5000`

## โครงสร้างโปรเจค

```
cybershield/
├── modules/                  # โมดูลหลัก
│   ├── port_scanner.py       # สแกนพอร์ต
│   ├── packet_analyzer.py    # วิเคราะห์แพ็กเก็ต
│   ├── password_analyzer.py  # วิเคราะห์รหัสผ่าน
│   ├── encryption_suite.py   # เครื่องมือเข้ารหัส
│   ├── subdomain_scanner.py  # สแกน subdomain
│   └── hash_cracker.py       # แคร็กแฮช
├── web/
│   └── index.html            # หน้า Dashboard
├── dashboard.py              # เซิร์ฟเวอร์ Flask
├── requirements.txt          # รายการ dependencies
└── README.md
```

## ฟีเจอร์หลัก

### วิเคราะห์รหัสผ่าน
- ตรวจความแรงแบบ realtime
- คำนวณ entropy (บิต)
- ประมาณเวลาที่จะถูกแคร็ก
- แนะนำวิธีปรับปรุง

### เครื่องมือเข้ารหัส
- Caesar Cipher (เลื่อนตัวอักษร)
- Vigenere Cipher (เข้ารหัสด้วยคีย์เวิร์ด)
- Base64 Encode
- MD5 / SHA-256 Hash

### เปรียบเทียบแฮช
- เทียบผลลัพธ์ของ MD5, SHA-1, SHA-256, SHA-512
- แสดงผลแบบ realtime

### สแกนพอร์ต (CLI)
- Multi-threaded TCP port scanner
- Banner grabbing
- ตรวจบริการที่ทำงานบนพอร์ต

## ผู้จัดทำ

**[ธัญเทพ ภัทรโกศล]**
- ผู้สมัครเข้าศึกษา สาขาวิศวกรรมคอมพิวเตอร์ (CEDT) จุฬาลงกรณ์มหาวิทยาลัย
- สนใจ: Cybersecurity, Network Security, Cryptography

## หมายเหตุ

เครื่องมือนี้สร้างเพื่อการศึกษาเท่านั้น ควรมีการอนุญาตก่อนสแกนระบบทุกครั้ง
