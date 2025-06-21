# SubLyze 🔍

**SubLyze** is a powerful subdomain enumeration & intelligence tool designed for penetration testers, bug bounty hunters, and red teamers.

---

## 🚀 Features

- 🔍 Passive Subdomain Enumeration (via crt.sh)
- ⚙️ Active DNS Brute-Forcing with wordlists
- 🧪 Subdomain Takeover Detection
- 🔀 Recursive Subdomain Expansion
- 📆 Save Output to File
- 📺 WAF/CDN Detection
- 🎈 Rich, Colorized Terminal UI
- ⚡ Mode Presets: `light`, `aggressive`
- ✅ Silent Mode for script integration
- 🌐 Custom DNS Resolver Support

---

## 📥 Installation

```bash
git clone https://github.com/r3xd1t/SubLyze.git
cd SubLyze
pip3 install -r requirements.txt
chmod +x sublyze.py
````

---

## 🎬 Usage

```bash
python3 sublyze.py -d example.com --all -w wordlists/common.txt --takeover
```

### 🔹 Flags

| Flag             | Description                                    |
| ---------------- | ---------------------------------------------- |
| `-d, --domain`   | Target domain                                  |
| `-w, --wordlist` | Wordlist file for brute-forcing                |
| `--passive`      | Use crt.sh for passive scan                    |
| `--active`       | Brute-force DNS subdomains                     |
| `--all`          | Run both passive and active scans              |
| `--takeover`     | Detect subdomain takeover vulnerabilities      |
| `--recursive`    | Recursive enumeration of discovered subdomains |
| `--output`       | Save discovered subdomains to file             |
| `--live`         | Check live subdomains from input file          |
| `--threads`      | Concurrent threads (default: 100)              |
| `--timeout`      | Request timeout (default: 10s)                 |
| `--delay`        | Delay between requests                         |
| `--dns-resolver` | Custom DNS server (e.g. 8.8.8.8)               |
| `--waf-check`    | Detect WAF/CDN services                        |
| `--mode`         | Set scan preset: `light` or `aggressive`       |
| `--silent`       | Hide banner output                             |

---

## 🔄 Examples

**Passive Only**

```bash
python3 sublyze.py -d example.com --passive
```

**Active with Wordlist**

```bash
python3 sublyze.py -d example.com --active -w wordlists/top1000.txt
```

**Full Recon + Takeover**

```bash
python3 sublyze.py -d example.com --all -w wordlists/huge.txt --takeover
```

---

## 📄 Sample Output

```text
🔍 Running passive enumeration for example.com
[Passive] www.example.com
[Passive] mail.example.com
[Active] admin.example.com
[Takeover Risk] dev.example.com ➔ GitHub Pages
[Recursive] test.www.example.com
[WAF] www.example.com ➔ Cloudflare

📄 Saved results to subdomains.txt
```

---

## 🧑‍💻 Author

* 💡 Made with ❤️ by **R3XD**
* 💻 GitHub: [r3xd1t](https://github.com/r3xd1t)

---

## 📃 License

Licensed under the MIT License.

````

---

**LICENSE**

```text
MIT License

Copyright (c) 2025 R3XD

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
````
