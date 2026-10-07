# CTF Toolkit

A modern, high-performance web-based toolkit designed for Capture The Flag (CTF) competitions, reverse engineering, and cybersecurity assessments. Fully client-side and completely offline capable.

## Features

### Cryptography Tools
- **Hash Generators**: MD5 (RFC 1321 UTF-8 byte stream compliant), SHA-1, SHA-256, SHA-384, SHA-512 via Web Crypto API.
- **Hash Candidate Identifier**: Instant signature detection for MD5, NTLM, SHA families, bcrypt, Argon2, and Unix crypt hashes.
- **Caesar Cipher**: Fast encoding, decoding, and automated 25-shift brute force output.
- **Substitution Ciphers**: ROT13, ROT47 (full ASCII printable shift), and Atbash cipher.
- **Vigenere Cipher**: Robust polyalphabetic cipher with key sanitization and error boundaries.
- **XOR Stream Cipher**: Multi-byte string XOR and full single-byte brute force (0x00 - 0xFF) with flag pattern scoring.

### Encoding & Decoding Tools
- **Base64 / Base64URL**: Standard Base64 and URL-safe Base64URL (RFC 4648) with non-crashing binary payload fallback.
- **Base32**: Full RFC 4648 Base32 alphabet encoder and decoder.
- **URL Encoder/Decoder**: Standard encoding plus full WAF bypass encoding (all characters converted to %XX).
- **Hex <-> ASCII**: Automatic prefix stripping (`0x`, `\x`, colons, spaces) and multi-byte UTF-8 preservation.
- **Binary <-> Text**: 8-bit stream parser with UTF-8 byte encoding.
- **Morse Code**: International Morse code encoder and decoder with word separation.
- **HTML Entities**: Safe entity encoding and decoding using DOMParser.

### Web Security Tools
- **JWT Inspector**: RFC 7519 Base64URL token decoder, timestamp formatter (`iat`, `exp`), and security vulnerability analysis.
- **JWT Forger (`alg: none`)**: Tamper token payload and forge unsigned tokens for algorithm confusion vulnerabilities.
- **Cookie Parser**: Strips header prefixes, parses multi-attribute cookies, and auto-detects nested Base64, URL, or JSON data.
- **HTTP Header Analyzer**: Security posture checker analyzing HSTS, CSP, X-Frame-Options, CORS, and cookie flags.
- **Reverse Shell Generator**: Interactive one-liner generator for Bash, Netcat, Python, PHP, PowerShell, Socat, and Node.js with Base64 WAF bypasses.
- **Exploitation Cheat Sheet**: Click-to-copy payloads for SQL Injection, SSTI, and Command Injection filter bypasses (`$IFS`, bash slices).

### Forensics & Miscellaneous Tools
- **File Magic Bytes Identifier**: Fast header signature lookup for PNG, JPEG, GIF, PDF, ZIP, ELF, Windows PE, PCAP, PCAPNG, 7z, and SQLite files.
- **CTF Flag Extractor**: Regex scanner extracting flags matching `flag{...}`, `ctf{...}`, or custom prefix patterns from memory dumps or raw text.
- **Text Case Converter**: Supports UPPERCASE, lowercase, Title Case, camelCase, snake_case, kebab-case, and CONSTANT_CASE.
- **Text Reversal**: Reverse characters, word order, or line order.
- **Word & Byte Counter**: Live character count, whitespace exclusion, word count, line count, and UTF-8 byte count.
- **Searchable ASCII Table**: Control, printable, and extended ASCII table with live search and filter capabilities.

## Architecture & Design System

- **Zero Dependencies**: Pure HTML5, CSS3, and modern vanilla JavaScript (ES6+). No external bundlers, node dependencies, or frameworks required.
- **Cyberpunk Dark Theme**: Engineered with high-contrast accessibility (WCAG AA compliant), terminal green accents (`#00FF41`), and dark slate surfaces (`#0a0e17`).
- **Complete Interactive States**: Every interactive surface supports tactile hover, physical active clicks (`scale(0.98)`), accessible focus rings, and inline feedback.
- **Offline First**: All operations run locally in the browser. Zero network requests, keeping secrets, tokens, and challenge flags private.

## Usage

1. Clone or download this repository:
   ```bash
   git clone https://github.com/AditCodeX/CTF-Toolkit-WebUI.git
   ```
2. Open `index.html` in any modern web browser (Chrome, Firefox, Safari, Edge).
3. Access tools via the navigation bar or category cards.

## Project Structure

```
CTF-Toolkit-WebUI/
├── index.html              # Central launch dashboard
├── css/
│   └── style.css           # Design system tokens and component styles
├── js/
│   ├── main.js             # Core toast notifications, copy-to-clipboard, nav handler
│   ├── crypto.js           # Hashes, Hash Identifier, Caesar, ROT, Vigenere, XOR
│   ├── encoding.js         # Base64, Base32, URL, Hex, Binary, Morse, HTML
│   ├── web.js              # JWT parser/forger, cookies, headers, reverse shell generator
│   └── utils.js            # Magic bytes, flag extractor, case converter, ASCII table
├── pages/
│   ├── crypto.html         # Cryptography suite
│   ├── encoding.html       # Encoding / Decoding suite
│   ├── web.html            # Web exploitation suite
│   └── misc.html           # Forensics and text utilities
├── design-system/          # Design system specifications
├── LICENSE                 # MIT License
└── README.md               # Documentation
```

## Contributing

Pull requests and issue submissions are welcome. Please ensure all contributions maintain zero runtime external dependencies and pass client-side verification.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

## Acknowledgments

Maintained by AditCodeX for CTF and cybersecurity enthusiasts.
