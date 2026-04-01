# 🔍 Windows Axios / sfrclak Compromise Scanner

Scanner PowerShell ini mendeteksi indikasi kompromi terkait supply‑chain attack **axios**, paket berbahaya **plain-crypto-js**, dan aktivitas C2 ke domain **sfrclak.com** pada sistem Windows.

Scanner ini cocok untuk:
- Incident Response (IR)
- Forensic triage
- Supply‑chain compromise detection
- Audit keamanan Node.js / npm

---

## 🚨 Fitur Utama

- 🔗 **C2 Detection** — memeriksa koneksi aktif ke `sfrclak.com`
- 🗂️ **Windows IOCs** — mendeteksi file berbahaya seperti `wt.exe`, `6202033.vbs`, `6202033.ps1`
- 📦 **npm Cache Inspection** — mencari jejak axios versi berbahaya & plain-crypto-js
- 🧵 **Process Scanner** — mendeteksi proses mencurigakan
- 📜 **PowerShell History Scanner** — mencari aktivitas instalasi paket
- 📁 **Folder Scan** dengan parameter `-ScanRoot`

---

## 📥 Download Script

File utama: [GET HERE - v1](https://raw.githubusercontent.com/diona-katzlein/windows-axios-compromise-scanner/refs/heads/main/scan-axios-windows-full.ps1)


---

## 🧰 Requirements

- Windows 10/11  
- PowerShell 5.1 atau PowerShell 7+  
- (Opsional) Node.js + npm untuk pemeriksaan cache

---

## ▶️ Cara Menjalankan

### 1. Buka PowerShell sebagai Administrator
Start → ketik **PowerShell** → **Run as Administrator**

---

### 2. Izinkan eksekusi script (jika belum)

```powershell Set-ExecutionPolicy Bypass -Scope Process -Force```

### Scan seluruh user profile (default)

```powershell -ExecutionPolicy Bypass -File .\scan-axios-windows-full.ps1```

### Scan folder atau project tertentu

```powershell -ExecutionPolicy Bypass -File .\scan-axios-windows-full.ps1 -ScanRoot "D:\path\to\project"```

## ✅ Scan Result — Axios / sfrclak Windows Scanner
<img width="1238" height="937" alt="image" src="https://github.com/user-attachments/assets/d9b91f0d-e20f-411e-9cfe-5ed943203606" />

## 1. File Hash IOCs
### Malicious Payloads
| SHA256 | Detection Name | Description |
| --- | --- | --- |
| ``e10b1fa84f1d6481625f741b69892780140d4e0e7769e7491e5f4d894c2e0e09`` | Trojan.JS.AXIOSDROP.THCCABF | ``setup.js`` — RAT dropper (plain-crypto-js@4.2.1 postinstall payload) |
| ``fcb81618bb15edfdedfb638b4c08a2af9cac9ecfa551af135a8402bf980375cf`` | Backdoor.Python.AXIOSRAT.THCCABF | ``ld.py`` — Linux Python RAT |
| ``f7d335205b8d7b20208fb3ef93ee6dc817905dc3ae0c10a0b164f4e7d07121cd`` | Trojan.PS1.AXIOSDROP.THCCABF | ``system.bat`` — Windows fileless loader |
| ``ed8560c1ac7ceb6983ba995124d5917dc1a00288912387a6389296637d5f815c`` | Trojan.PS1.AXIOSDROP.THCCABF | ``system.bat`` — Windows fileless loader |
| ``617b67a8e1210e4fc87c92d1d1da45a2f311c08d26e89b12307cf583c900d101`` | Trojan.PS1.AXIOSDROP.THCCABF | ``system.bat`` — Windows fileless loader |

## 2. Malicious npm Packages
| Package | SHA‑1 |
| --- | --- |
| ``axios@1.14.1`` | ``2553649f2322049666871cea80a5d0d6adc700ca`` |
| ``axios@0.30.4`` | ``d6f3f62fd3b9f5432f5782b62d8cfd5247d5ee71`` |
| ``plain-crypto-js@4.2.1`` | ``07d889e2dadce6f3910dcbc253317d28ca61c766`` |
### Catatan: 
``plain-crypto-js`` adalah paket 100% malicious dan tidak pernah legitimate.

## 3. Network Indicators
| Indicator | Value |
| --- | --- |
| **C&C domain** | ``sfrclak.com`` |
| **C&C domain** | ``callnrwise.com`` |
| **C&C IP** | ``142.11.206.73`` |
| **C&C URL** | ``http://sfrclak.com:8000/6202033`` |
| **POST body (macOS)** | ``packages.npm.org/product0`` |
| **POST body (Windows)** | ``packages.npm.org/product1`` |
| **POST body (Linux)** | ``packages.npm.org/product2`` |

## 4. File System Artifacts
| Platform | Path |
| --- | --- |
| **macOS** | ``/Library/Caches/com.apple.act.mond`` |
| **Windows (persistent)** | ``%PROGRAMDATA%\\wt.exe`` |
| **Windows (temp)** | ``%TEMP%\\6202033.vbs``, ``%TEMP%\\6202033.ps1`` |
| **Linux** | ``/tmp/ld.py`` |

