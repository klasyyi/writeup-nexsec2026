# NexSec 2026 CTF Writeups (Gemini flash wrote this writeup)

Repository containing writeups and solve scripts for **NexSec CTF 2026**.

## Solved Challenges

| Category | Challenge | Writeup | Reference |
| :--- | :--- | :--- | :--- |
| **Forensics** | Dead Drop Latte | [Writeup & Exploit](forensics/dead-drop-latte/) | [DeepSeek Session](https://chat.deepseek.com/share/0izrlmc9invir9zffr) |
| **Forensics** | n8n | [Writeup & Exploit](forensics/n8n/) | [DeepSeek Session](https://chat.deepseek.com/share/jd8mnm2z53dzbu8k7x) |
| **Crypto** | Paradise | [Writeup & Exploit](crypto/mersenne-twister/) | [DeepSeek Session](https://chat.deepseek.com/share/2e0hdtt83v6ocj9iqf) |
| **Crypto** | Mirror Image | [Writeup & Exploit](crypto/mirror-image/) | [DeepSeek Session](https://chat.deepseek.com/share/uk97mksa8d2tucubvz) |
| **Reverse** | матрёшка (Matryoshka) | [Writeup & Exploit](reverse/matryoshka/) | [DeepSeek Session](https://chat.deepseek.com/share/pfw85puth4sur5t0sx) |
| **Misc** | Antivist | [Writeup](misc/Antivist/) | [DeepSeek Session](https://chat.deepseek.com/share/80ksxx3a2gtqfhboj2) |
| **Misc** | Neverland's Cave | [Writeup & Exploit](misc/neverlands-cave/) | [DeepSeek Session](https://chat.deepseek.com/share/2uv3561mo631dw4eha) |

---

## Directory Structure

```text
writeup-nexsec2026/
├── README.md
├── crypto/
│   ├── mersenne-twister/
│   │   ├── README.md       # Detailed technical writeup
│   │   ├── solve.py        # Complete exploit script
│   │   └── challenge.py    # Original challenge source
│   └── mirror-image/
│       ├── README.md       # Detailed technical writeup
│       ├── solve.py        # Complete exploit script
│       └── challenge.py    # Original challenge source
├── forensics/
│   ├── dead-drop-latte/
│   │   ├── README.md       # Detailed technical writeup
│   │   └── solve.py        # Complete exploit script
│   └── n8n/
│       ├── README.md       # Detailed technical writeup
│       └── solve.py        # Complete exploit script
├── misc/
│   ├── Antivist/
│   │   └── README.md       # Detailed technical writeup
│   └── neverlands-cave/
│       ├── README.md       # Detailed technical writeup
│       ├── solve.py        # Complete exploit script
│       ├── app.py          # Original challenge source
│       ├── Dockerfile      # Container configuration
│       ├── index.html      # Web preview template
│       └── requirements.txt# Python requirements
└── reverse/
    └── matryoshka/
        ├── README.md       # Detailed technical writeup
        ├── solve.py        # Complete exploit script
        ├── decrypted_doll-0.dll
        └── decrypted_doll-1.dll
```
