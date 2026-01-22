<!-- 
SEO Keywords: NullSec Stealth, evasion tools, anti-forensics, steganography, covert channels,
process hiding, AV bypass, EDR evasion, fileless malware, memory injection,
bad-antics, NullSec Framework, red team tools, stealth toolkit, evasion framework
-->

<div align="center">

# 👻 NullSec Stealth

### Advanced Evasion & Anti-Forensics Toolkit

[![Discord](https://img.shields.io/badge/🔑_GET_KEYS-discord.gg/killers-5865F2?style=for-the-badge&logo=discord&logoColor=white)](https://discord.gg/killers)
[![GitHub](https://img.shields.io/badge/GitHub-bad--antics-181717?style=for-the-badge&logo=github&logoColor=white)](https://github.com/bad-antics)
[![License](https://img.shields.io/badge/License-NSTL--XXX-red?style=for-the-badge)](LICENSE)

[![Crystal](https://img.shields.io/badge/Crystal-000000?style=for-the-badge&logo=crystal&logoColor=white)]()
[![Lua](https://img.shields.io/badge/Lua-2C2D72?style=for-the-badge&logo=lua&logoColor=white)]()
[![D](https://img.shields.io/badge/D-B03931?style=for-the-badge&logo=d&logoColor=white)]()
[![Haskell](https://img.shields.io/badge/Haskell-5D4F85?style=for-the-badge&logo=haskell&logoColor=white)]()
[![V](https://img.shields.io/badge/V-5D87BF?style=for-the-badge&logo=v&logoColor=white)]()

```
    ███▄    █  █    ██  ██▓     ██▓      ██████ ▓█████  ▄████▄  
    ██ ▀█   █  ██  ▓██▒▓██▒    ▓██▒    ▒██    ▒ ▓█   ▀ ▒██▀ ▀█  
   ▓██  ▀█ ██▒▓██  ▒██░▒██░    ▒██░    ░ ▓██▄   ▒███   ▒▓█    ▄ 
   ▓██▒  ▐▌██▒▓▓█  ░██░▒██░    ▒██░      ▒   ██▒▒▓█  ▄ ▒▓▓▄ ▄██▒
   ▒██░   ▓██░▒▒█████▓ ░██████▒░██████▒▒██████▒▒░▒████▒▒ ▓███▀ ░
   ░ ▒░   ▒ ▒ ░▒▓▒ ▒ ▒ ░ ▒░▓  ░░ ▒░▓  ░▒ ▒▓▒ ▒ ░░░ ▒░ ░░ ░▒ ▒  ░
     ░    ░    ░   ░   ░         ░            ░   ░   ░        
   ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
   █░░░░░░░░░░░░░░░░░░░ S T E A L T H ░░░░░░░░░░░░░░░░░░░░░░░░█
   ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀
                       bad-antics
```

### 🔓 **[Join discord.gg/killers](https://discord.gg/killers)** for premium features!

</div>

---

## 🎯 Features

| Tool | Language | Description | Free | Premium |
|------|----------|-------------|------|---------|
| **stegohide** | Crystal | Advanced steganography encoder | ✅ | 🔥 |
| **procmask** | Lua | Process name/memory masking | ✅ | 🔥 |
| **timewarp** | D | Timestamp manipulation | ✅ | 🔥 |
| **cryptchan** | Haskell | Encrypted covert channels | ❌ | 🔥 |
| **ghostmem** | V | Fileless memory execution | ❌ | 🔥 |
| **avbypass** | Crystal | AV signature evasion | ❌ | 🔥 |

---

## 📁 Structure

```
nullsec-stealth/
├── crystal/
│   └── stegohide.cr      # Steganography encoder/decoder
├── lua/
│   └── procmask.lua      # Process masking utility
├── dlang/
│   └── timewarp.d        # Timestamp manipulation
├── haskell/
│   └── cryptchan.hs      # Encrypted covert channels
└── vlang/
    └── ghostmem.v        # Fileless memory execution
```

---

## 🔧 Installation

### Crystal - StegoHide
```bash
cd crystal
crystal build stegohide.cr --release -o stegohide
./stegohide encode -i secret.txt -c cover.png -o output.png
```

### Lua - ProcMask
```bash
cd lua
lua procmask.lua --pid 1234 --name "systemd"
```

### D - TimeWarp
```bash
cd dlang
dmd -release -O timewarp.d -of=timewarp
./timewarp --file target.exe --time "2020-01-01 00:00:00"
```

### Haskell - CryptChan
```bash
cd haskell
ghc -O2 cryptchan.hs -o cryptchan
./cryptchan --mode server --port 443 --key mykey
```

### V - GhostMem
```bash
cd vlang
v -prod ghostmem.v -o ghostmem
./ghostmem --payload shellcode.bin --target pid
```

---

## 💀 Tool Details

### StegoHide (Crystal)
Advanced steganography tool supporting multiple carrier formats:
- **PNG/BMP** - LSB encoding with encryption
- **JPEG** - DCT coefficient manipulation
- **WAV/MP3** - Audio spectrum hiding
- **PDF** - Whitespace encoding
- **AES-256** encryption for payloads

### ProcMask (Lua)
Process evasion and masking utility:
- Rename running process in memory
- Mask command line arguments
- Hollow process injection setup
- Parent PID spoofing preparation
- Module list manipulation

### TimeWarp (D)
Timestamp manipulation for anti-forensics:
- Modify MACB timestamps (Modified, Accessed, Changed, Birth)
- Recursive directory timestamp matching
- Random timestamp within range
- Clone timestamps from reference file
- NTFS $STANDARD_INFO and $FILE_NAME manipulation

### CryptChan (Haskell)
Encrypted covert communication channels:
- DNS tunneling with encryption
- ICMP covert channel
- HTTP header smuggling
- TLS certificate field hiding
- Timing-based channels

### GhostMem (V)
Fileless payload execution:
- Direct syscall execution
- Memory-only payload loading
- Process hollowing
- Module stomping
- Thread execution hijacking

---

## ⚠️ Legal Disclaimer

**FOR EDUCATIONAL AND AUTHORIZED SECURITY TESTING ONLY**

These tools are designed for:
- Red team engagements
- Penetration testing
- Security research
- Educational purposes

Unauthorized use against systems you don't own or have permission to test is illegal.

---

## 📜 License

NullSec Proprietary License - See [LICENSE](LICENSE) for details.

Premium features require a valid key from [discord.gg/killers](https://discord.gg/killers)

---

<div align="center">

**[Discord](https://discord.gg/killers)** • **[GitHub](https://github.com/bad-antics)** • **[Tools](https://github.com/bad-antics?tab=repositories)**

*Made with 💀 by bad-antics*

</div>
