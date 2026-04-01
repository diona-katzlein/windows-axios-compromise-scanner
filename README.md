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

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force

