# OSINTBABY
OSINTBABY is a modular command-line OSINT tool built with Python for collecting intelligence from free public sources. It provides security researchers and penetration testers a unified interface to perform reconnaissance on domains, IP addresses, emails, usernames, phone numbers, and file hashes efficiently and legally.

## 📖 Description

**OSINT CLI** is a comprehensive, modular command-line tool designed for gathering Open Source Intelligence from free public sources. Built with Python, it provides security researchers, penetration testers, and cybersecurity professionals with a unified interface to perform reconnaissance on domains, IP addresses, emails, usernames, phone numbers, and file hashes.

### Why OSINT CLI?

- 🆓 **100% Free** - Uses only free OSINT sources and APIs
- 🚀 **Fast** - Asynchronous requests for quick results
- 🎨 **Beautiful Output** - Rich terminal formatting with colors and tables
- 🔧 **Modular** - Easy to extend with new modules
- 📦 **Portable** - Single tool, multiple capabilities
- 🐧 **Linux Native** - Designed for Linux with full support

---

## ✨ Features

| Feature                      |                  Description                                           |
|------------------------------|------------------------------------------------------------------------|
| 🌐 **Domain Recon**          | DNS records, WHOIS, subdomains, SSL certificates, technology detection |
| 🔢 **IP Investigation**      | Geolocation, ASN info, reverse DNS, blacklist checking, port scanning  |
| 📧 **Email OSINT**           | Validation, breach checking, Gravatar lookup, domain analysis          |
| 👤 **Username Search**       | Check 20+ social platforms simultaneously                              |
| 📱 **Phone Lookup**          | Country detection, carrier identification, validation                  |
| 🔐 **Hash Analysis**         | VirusTotal, MalwareBazaar, malware identification                      |
| 🔍 **Shodan Integration**    | Free InternetDB lookup, vulnerability detection                        |
| 📊 **Multiple Formats**      | Table, JSON output support                                             |

---

## 💻 Requirements

### System Requirements

| Requirement | Minimum                                                         |
|-------------|-----------------------------------------------------------------|
| OS          | Linux (Ubuntu 18.04+, Debian 10+, CentOS 7+, Fedora 30+, Arch)  |
| Python      | 3.8 or higher                                                   |
| RAM         | 512 MB                                                          |
| Storage     | 100 MB                                                          |
| Network     | Internet connection                                             |

### Check Your System

```bash
# Check Python version (must be 3.8+)
python3 --version

# Check pip
pip3 --version

# Check git
git --version
Below is a **clean, professional `README.md`** you can **copy-paste directly** into your project.
It includes **project overview, setup, virtual environment, installation, and run instructions**.

---

```markdown
# 🍼 OSINTBABY

**OSINTBABY** is a comprehensive, modular command-line OSINT (Open Source Intelligence) tool built with Python.  
It enables security researchers, penetration testers, and cybersecurity professionals to gather intelligence from **free and public sources** using a single, unified CLI interface.

The tool supports reconnaissance on:
- Domains
- IP addresses
- Email addresses
- Usernames
- Phone numbers (basic)
- File metadata & hashes

⚠️ OSINTBABY uses **only legal, publicly available data**.

---

## 🚀 Features

- Modular and extensible architecture
- Fully command-line based
- No paid APIs required
- Beginner-friendly and SOC/OSCP ready
- Runs on Linux, Windows, and macOS
- Virtual environment support

---

## 🛠️ Requirements

- Python **3.9 or higher**
- Git
- Internet connection
- (Optional) Linux / Kali Linux recommended

---

## ⚙️ Setup Instructions

### 1️⃣ Clone the Repository
```bash
git clone https://github.com/anandthosar03-hub/OSINTBABY.git
cd OSINTBABY
````

---

### 2️⃣ Create Virtual Environment

#### Linux / macOS

```bash
python3 -m venv venv
source venv/bin/activate
```

#### Windows (PowerShell)

```powershell
python -m venv venv
venv\Scripts\Activate
```

---

### 3️⃣ Install Dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

---

## ▶️ Run Instructions

---

## 🟢 Step 1: Open Terminal & Go to Project Folder

```bash
git clone https://github.com/anandthosar03-hub/OSINTBABY.git
cd OSINTBABY
```

---

## 🟢 Step 2: Create Virtual Environment (First Time Only)

```bash
python3 -m venv venv
```

Activate it:

```bash
source venv/bin/activate
```

You should see:

```bash
(venv) user@linux:~/OSINTBABY$
```

---

## 🟢 Step 3: Install Dependencies (First Time Only)

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

---

## 🟢 Step 4: Run OSINTBABY Help Menu

```bash
python3 main.py --help
```

This confirms the tool is working.

---

## 🟢 Step 5: Run OSINTBABY Modules (Examples)

### 🔹 IP Intelligence

```bash
python3 main.py ip 8.8.8.8
```

---

### 🔹 Domain Reconnaissance

```bash
python3 main.py domain google.com
```

---

### 🔹 Email OSINT

```bash
python3 main.py email test@example.com
```

---

### 🔹 Username Enumeration

```bash
python3 main.py username torvalds
```

---

### 🔹 Website Header Analysis

```bash
python3 main.py web https://example.com
```

---

### 🔹 Metadata Extraction

```bash
python3 main.py metadata sample.jpg
```

(Ensure `exiftool` is installed)

```bash
sudo apt install exiftool -y
```

---

### 🔹 Dark Web Search (Legal)

```bash
python3 main.py darkweb bitcoin
```

---

## 🟢 Step 6: Deactivate Virtual Environment (When Done)

```bash
deactivate
```

## ✅ Best Practice (Optional)

Add executable permission:

```bash
chmod +x main.py
./main.py ip 8.8.8.8
```
Display help menu:

```bash
python main.py --help
```

### Example Commands

```bash
python main.py ip 8.8.8.8
python main.py domain google.com
python main.py email test@example.com
python main.py username torvalds
python main.py web https://example.com
python main.py metadata sample.jpg
```

---

## 🔐 Legal Disclaimer

OSINTBABY is intended **for educational and defensive security purposes only**.
The developers are not responsible for misuse of this tool.
Always follow local laws and ethical guidelines when performing OSINT.

---
---

## ⭐ Credits

Developed with ❤️ using Python
Designed for cybersecurity learners and professionals.

