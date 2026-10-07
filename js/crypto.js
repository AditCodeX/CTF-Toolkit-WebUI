// Cryptography tools for CTF Toolkit

// Hash generation using Web Crypto API and UTF-8 compliant MD5
async function generateHashes() {
    const input = document.getElementById('hashInput').value;
    if (!input) {
        ctfToolkit.showToast('Please enter some text to hash', 'error');
        return;
    }

    const output = document.getElementById('hashOutput');
    
    try {
        const encoder = new TextEncoder();
        const data = encoder.encode(input);
        
        let results = [];
        
        // MD5 (UTF-8 byte stream implementation)
        const md5Hash = simpleMD5(input);
        results.push(`MD5:    ${md5Hash}`);

        // Web Crypto API Algorithms
        const algorithms = [
            { name: 'SHA-1', label: 'SHA-1:  ' },
            { name: 'SHA-256', label: 'SHA-256:' },
            { name: 'SHA-384', label: 'SHA-384:' },
            { name: 'SHA-512', label: 'SHA-512:' }
        ];
        
        for (const algo of algorithms) {
            const hashBuffer = await crypto.subtle.digest(algo.name, data);
            const hashArray = Array.from(new Uint8Array(hashBuffer));
            const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
            results.push(`${algo.label} ${hashHex}`);
        }
        
        ctfToolkit.formatOutput(output, results.join('\n'));
        ctfToolkit.toggleOutput('hashOutputSection', true);
    } catch (error) {
        ctfToolkit.formatOutput(output, 'Error generating hashes: ' + error.message, true);
        ctfToolkit.toggleOutput('hashOutputSection', true);
    }
}

// Identify Hash Algorithm Candidates
function identifyHashCandidates() {
    const hash = document.getElementById('hashIdentifyInput').value.trim();
    if (!hash) {
        ctfToolkit.showToast('Please enter a hash to identify', 'error');
        return;
    }

    const len = hash.length;
    const isHex = /^[0-9a-fA-F]+$/.test(hash);
    const candidates = [];

    if (hash.startsWith('$1$')) candidates.push('MD5-crypt (Unix)');
    if (/^\$2[aby]\$/.test(hash)) candidates.push('bcrypt');
    if (hash.startsWith('$5$')) candidates.push('SHA-256-crypt');
    if (hash.startsWith('$6$')) candidates.push('SHA-512-crypt');
    if (hash.startsWith('$argon2')) candidates.push('Argon2');
    if (hash.startsWith('$pbkdf2')) candidates.push('PBKDF2');

    if (isHex) {
        if (len === 32) candidates.push('MD5', 'NTLM', 'MD4');
        else if (len === 40) candidates.push('SHA-1', 'RIPEMD-160');
        else if (len === 56) candidates.push('SHA-224');
        else if (len === 64) candidates.push('SHA-256', 'Keccak-256', 'BLAKE2s');
        else if (len === 96) candidates.push('SHA-384');
        else if (len === 128) candidates.push('SHA-512', 'Whirlpool', 'BLAKE2b');
    }

    const output = document.getElementById('hashIdentifyOutput');
    if (candidates.length > 0) {
        let result = `Analyzed Hash Length: ${len} characters (${isHex ? 'Hexadecimal' : 'Non-Hex'})\n\nProbable Algorithms:\n`;
        candidates.forEach(c => {
            result += `• ${c}\n`;
        });
        ctfToolkit.formatOutput(output, result);
    } else {
        ctfToolkit.formatOutput(output, `Length: ${len} chars (${isHex ? 'Hex' : 'Non-hex'}).\nNo definitive standard algorithm matched. Check for custom hash, salts, or truncated outputs.`, true);
    }
    ctfToolkit.toggleOutput('hashIdentifyOutputSection', true);
}

// UTF-8 compliant MD5 implementation
function simpleMD5(string) {
    function RotateLeft(lValue, iShiftBits) {
        return (lValue << iShiftBits) | (lValue >>> (32 - iShiftBits));
    }
    function AddUnsigned(lX, lY) {
        var lX4, lY4, lX8, lY8, lResult;
        lX8 = (lX & 0x80000000);
        lY8 = (lY & 0x80000000);
        lX4 = (lX & 0x40000000);
        lY4 = (lY & 0x40000000);
        lResult = (lX & 0x3FFFFFFF) + (lY & 0x3FFFFFFF);
        if (lX4 & lY4) return (lResult ^ 0x80000000 ^ lX8 ^ lY8);
        if (lX4 | lY4) {
            if (lResult & 0x40000000) return (lResult ^ 0xC0000000 ^ lX8 ^ lY8);
            else return (lResult ^ 0x40000000 ^ lX8 ^ lY8);
        } else return (lResult ^ lX8 ^ lY8);
    }
    function F(x, y, z) { return (x & y) | ((~x) & z); }
    function G(x, y, z) { return (x & z) | (y & (~z)); }
    function H(x, y, z) { return (x ^ y ^ z); }
    function I(x, y, z) { return (y ^ (x | (~z))); }

    function FF(a, b, c, d, x, s, ac) {
        a = AddUnsigned(a, AddUnsigned(AddUnsigned(F(b, c, d), x), ac));
        return AddUnsigned(RotateLeft(a, s), b);
    }
    function GG(a, b, c, d, x, s, ac) {
        a = AddUnsigned(a, AddUnsigned(AddUnsigned(G(b, c, d), x), ac));
        return AddUnsigned(RotateLeft(a, s), b);
    }
    function HH(a, b, c, d, x, s, ac) {
        a = AddUnsigned(a, AddUnsigned(AddUnsigned(H(b, c, d), x), ac));
        return AddUnsigned(RotateLeft(a, s), b);
    }
    function II(a, b, c, d, x, s, ac) {
        a = AddUnsigned(a, AddUnsigned(AddUnsigned(I(b, c, d), x), ac));
        return AddUnsigned(RotateLeft(a, s), b);
    }

    const utf8Bytes = Array.from(new TextEncoder().encode(string));
    const msgLen = utf8Bytes.length;
    const numWords = (((msgLen + 8) - ((msgLen + 8) % 64)) / 64 + 1) * 16;
    const words = new Array(numWords).fill(0);

    for (let i = 0; i < msgLen; i++) {
        const wordIndex = Math.floor(i / 4);
        const bytePos = (i % 4) * 8;
        words[wordIndex] |= (utf8Bytes[i] << bytePos);
    }

    words[Math.floor(msgLen / 4)] |= (0x80 << ((msgLen % 4) * 8));
    words[numWords - 2] = (msgLen * 8) & 0xFFFFFFFF;
    words[numWords - 1] = Math.floor((msgLen * 8) / 0x100000000);

    let a = 0x67452301, b = 0xEFCDAB89, c = 0x98BADCFE, d = 0x10325476;
    const S11 = 7, S12 = 12, S13 = 17, S14 = 22;
    const S21 = 5, S22 = 9, S23 = 14, S24 = 20;
    const S31 = 4, S32 = 11, S33 = 16, S34 = 23;
    const S41 = 6, S42 = 10, S43 = 15, S44 = 21;

    for (let k = 0; k < words.length; k += 16) {
        let AA = a, BB = b, CC = c, DD = d;
        a = FF(a, b, c, d, words[k + 0], S11, 0xD76AA478);
        d = FF(d, a, b, c, words[k + 1], S12, 0xE8C7B756);
        c = FF(c, d, a, b, words[k + 2], S13, 0x242070DB);
        b = FF(b, c, d, a, words[k + 3], S14, 0xC1BDCEEE);
        a = FF(a, b, c, d, words[k + 4], S11, 0xF57C0FAF);
        d = FF(d, a, b, c, words[k + 5], S12, 0x4787C62A);
        c = FF(c, d, a, b, words[k + 6], S13, 0xA8304613);
        b = FF(b, c, d, a, words[k + 7], S14, 0xFD469501);
        a = FF(a, b, c, d, words[k + 8], S11, 0x698098D8);
        d = FF(d, a, b, c, words[k + 9], S12, 0x8B44F7AF);
        c = FF(c, d, a, b, words[k + 10], S13, 0xFFFF5BB1);
        b = FF(b, c, d, a, words[k + 11], S14, 0x895CD7BE);
        a = FF(a, b, c, d, words[k + 12], S11, 0x6B901122);
        d = FF(d, a, b, c, words[k + 13], S12, 0xFD987193);
        c = FF(c, d, a, b, words[k + 14], S13, 0xA679438E);
        b = FF(b, c, d, a, words[k + 15], S14, 0x49B40821);

        a = GG(a, b, c, d, words[k + 1], S21, 0xF61E2562);
        d = GG(d, a, b, c, words[k + 6], S22, 0xC040B340);
        c = GG(c, d, a, b, words[k + 11], S23, 0x265E5A51);
        b = GG(b, c, d, a, words[k + 0], S24, 0xE9B6C7AA);
        a = GG(a, b, c, d, words[k + 5], S21, 0xD62F105D);
        d = GG(d, a, b, c, words[k + 10], S22, 0x2441453);
        c = GG(c, d, a, b, words[k + 15], S23, 0xD8A1E681);
        b = GG(b, c, d, a, words[k + 4], S24, 0xE7D3FBC8);
        a = GG(a, b, c, d, words[k + 9], S21, 0x21E1CDE6);
        d = GG(d, a, b, c, words[k + 14], S22, 0xC33707D6);
        c = GG(c, d, a, b, words[k + 3], S23, 0xF4D50D87);
        b = GG(b, c, d, a, words[k + 8], S24, 0x455A14ED);
        a = GG(a, b, c, d, words[k + 13], S21, 0xA9E3E905);
        d = GG(d, a, b, c, words[k + 2], S22, 0xFCEFA3F8);
        c = GG(c, d, a, b, words[k + 7], S23, 0x676F02D9);
        b = GG(b, c, d, a, words[k + 12], S24, 0x8D2A4C8A);

        a = HH(a, b, c, d, words[k + 5], S31, 0xFFFA3942);
        d = HH(d, a, b, c, words[k + 8], S32, 0x8771F681);
        c = HH(c, d, a, b, words[k + 11], S33, 0x6D9D6122);
        b = HH(b, c, d, a, words[k + 14], S34, 0xFDE5380C);
        a = HH(a, b, c, d, words[k + 1], S31, 0xA4BEEA44);
        d = HH(d, a, b, c, words[k + 4], S32, 0x4BDECFA9);
        c = HH(c, d, a, b, words[k + 7], S33, 0xF6BB4B60);
        b = HH(b, c, d, a, words[k + 10], S34, 0xBEBFBC70);
        a = HH(a, b, c, d, words[k + 13], S31, 0x289B7EC6);
        d = HH(d, a, b, c, words[k + 0], S32, 0xEAA127FA);
        c = HH(c, d, a, b, words[k + 3], S33, 0xD4EF3085);
        b = HH(b, c, d, a, words[k + 6], S34, 0x4881D05);
        a = HH(a, b, c, d, words[k + 9], S31, 0xD9D4D039);
        d = HH(d, a, b, c, words[k + 12], S32, 0xE6DB99E5);
        c = HH(c, d, a, b, words[k + 15], S33, 0x1FA27CF8);
        b = HH(b, c, d, a, words[k + 2], S34, 0xC4AC5665);

        a = II(a, b, c, d, words[k + 0], S41, 0xF4292244);
        d = II(d, a, b, c, words[k + 7], S42, 0x432AFF97);
        c = II(c, d, a, b, words[k + 14], S43, 0xAB9423A7);
        b = II(b, c, d, a, words[k + 5], S44, 0xFC93A039);
        a = II(a, b, c, d, words[k + 12], S41, 0x655B59C3);
        d = II(d, a, b, c, words[k + 3], S42, 0x8F0CCC92);
        c = II(c, d, a, b, words[k + 10], S43, 0xFFEFF47D);
        b = II(b, c, d, a, words[k + 1], S44, 0x85845DD1);
        a = II(a, b, c, d, words[k + 8], S41, 0x6FA87E4F);
        d = II(d, a, b, c, words[k + 15], S42, 0xFE2CE6E0);
        c = II(c, d, a, b, words[k + 6], S43, 0xA3014314);
        b = II(b, c, d, a, words[k + 13], S44, 0x4E0811A1);
        a = II(a, b, c, d, words[k + 4], S41, 0xF7537E82);
        d = II(d, a, b, c, words[k + 11], S42, 0xBD3AF235);
        c = II(c, d, a, b, words[k + 2], S43, 0x2AD7D2BB);
        b = II(b, c, d, a, words[k + 9], S44, 0xEB86D391);

        a = AddUnsigned(a, AA);
        b = AddUnsigned(b, BB);
        c = AddUnsigned(c, CC);
        d = AddUnsigned(d, DD);
    }

    function wordToHex(val) {
        let res = '';
        for (let i = 0; i <= 3; i++) {
            const byte = (val >>> (i * 8)) & 255;
            res += byte.toString(16).padStart(2, '0');
        }
        return res;
    }

    return (wordToHex(a) + wordToHex(b) + wordToHex(c) + wordToHex(d)).toLowerCase();
}

// Caesar Cipher
function caesarEncode() {
    const input = document.getElementById('caesarInput').value;
    const shift = parseInt(document.getElementById('caesarShift').value, 10);
    
    if (!input) {
        ctfToolkit.showToast('Please enter some text', 'error');
        return;
    }
    
    const result = caesarCipher(input, shift);
    ctfToolkit.formatOutput(document.getElementById('caesarOutput'), result);
    ctfToolkit.toggleOutput('caesarOutputSection', true);
}

function caesarDecode() {
    const input = document.getElementById('caesarInput').value;
    const shift = parseInt(document.getElementById('caesarShift').value, 10);
    
    if (!input) {
        ctfToolkit.showToast('Please enter some text', 'error');
        return;
    }
    
    const result = caesarCipher(input, -shift);
    ctfToolkit.formatOutput(document.getElementById('caesarOutput'), result);
    ctfToolkit.toggleOutput('caesarOutputSection', true);
}

function caesarBruteForce() {
    const input = document.getElementById('caesarInput').value;
    if (!input) {
        ctfToolkit.showToast('Please enter text to brute force', 'error');
        return;
    }

    let results = [];
    for (let s = 1; s <= 25; s++) {
        results.push(`Shift +${String(s).padStart(2, '0')}: ${caesarCipher(input, s)}`);
    }

    ctfToolkit.formatOutput(document.getElementById('caesarOutput'), results.join('\n'));
    ctfToolkit.toggleOutput('caesarOutputSection', true);
}

function caesarCipher(text, shift) {
    const normShift = ((shift % 26) + 26) % 26;
    return text.replace(/[a-zA-Z]/g, function(char) {
        const code = char.charCodeAt(0);
        const isUpperCase = code >= 65 && code <= 90;
        const base = isUpperCase ? 65 : 97;
        return String.fromCharCode(((code - base + normShift) % 26) + base);
    });
}

// ROT13
function rot13Transform() {
    const input = document.getElementById('rot13Input').value;
    if (!input) {
        ctfToolkit.showToast('Please enter text for ROT13', 'error');
        return;
    }
    
    const result = caesarCipher(input, 13);
    ctfToolkit.formatOutput(document.getElementById('rot13Output'), result);
    ctfToolkit.toggleOutput('rot13OutputSection', true);
}

// ROT47 (Full ASCII printable shift)
function rot47Transform() {
    const input = document.getElementById('rot47Input').value;
    if (!input) {
        ctfToolkit.showToast('Please enter text for ROT47', 'error');
        return;
    }

    const result = input.replace(/[\x21-\x7E]/g, function(char) {
        return String.fromCharCode(33 + ((char.charCodeAt(0) - 33 + 47) % 94));
    });

    ctfToolkit.formatOutput(document.getElementById('rot47Output'), result);
    ctfToolkit.toggleOutput('rot47OutputSection', true);
}

// Atbash Cipher (A <-> Z substitution)
function atbashTransform() {
    const input = document.getElementById('atbashInput').value;
    if (!input) {
        ctfToolkit.showToast('Please enter text for Atbash', 'error');
        return;
    }

    const result = input.replace(/[a-zA-Z]/g, function(char) {
        const code = char.charCodeAt(0);
        const isUpper = code >= 65 && code <= 90;
        return String.fromCharCode(isUpper ? 90 - (code - 65) : 122 - (code - 97));
    });

    ctfToolkit.formatOutput(document.getElementById('atbashOutput'), result);
    ctfToolkit.toggleOutput('atbashOutputSection', true);
}

// Vigenere Cipher
function vigenereEncode() {
    const input = document.getElementById('vigenereInput').value;
    const key = document.getElementById('vigenereKey').value;
    
    if (!input || !key) {
        ctfToolkit.showToast('Please enter both text and key', 'error');
        return;
    }
    
    try {
        const result = vigenereCipher(input, key, true);
        ctfToolkit.formatOutput(document.getElementById('vigenereOutput'), result);
        ctfToolkit.toggleOutput('vigenereOutputSection', true);
    } catch (err) {
        ctfToolkit.formatOutput(document.getElementById('vigenereOutput'), err.message, true);
        ctfToolkit.toggleOutput('vigenereOutputSection', true);
    }
}

function vigenereDecode() {
    const input = document.getElementById('vigenereInput').value;
    const key = document.getElementById('vigenereKey').value;
    
    if (!input || !key) {
        ctfToolkit.showToast('Please enter both text and key', 'error');
        return;
    }
    
    try {
        const result = vigenereCipher(input, key, false);
        ctfToolkit.formatOutput(document.getElementById('vigenereOutput'), result);
        ctfToolkit.toggleOutput('vigenereOutputSection', true);
    } catch (err) {
        ctfToolkit.formatOutput(document.getElementById('vigenereOutput'), err.message, true);
        ctfToolkit.toggleOutput('vigenereOutputSection', true);
    }
}

function vigenereCipher(text, key, encode) {
    const keyUpper = key.toUpperCase().replace(/[^A-Z]/g, '');
    if (keyUpper.length === 0) {
        throw new Error('Key must contain at least one alphabetic letter (A-Z)');
    }
    let keyIndex = 0;
    
    return text.replace(/[a-zA-Z]/g, function(char) {
        const code = char.charCodeAt(0);
        const isUpperCase = code >= 65 && code <= 90;
        const base = isUpperCase ? 65 : 97;
        
        const shift = keyUpper.charCodeAt(keyIndex % keyUpper.length) - 65;
        keyIndex++;
        
        const effShift = encode ? shift : ((26 - (shift % 26)) % 26);
        return String.fromCharCode(((code - base + effShift) % 26) + base);
    });
}

// XOR Cipher (Text / Hex & Brute Force)
function xorEncryptDecrypt() {
    const input = document.getElementById('xorInput').value;
    const key = document.getElementById('xorKey').value;

    if (!input || !key) {
        ctfToolkit.showToast('Please enter both text and key for XOR', 'error');
        return;
    }

    let textBytes = Array.from(new TextEncoder().encode(input));
    let keyBytes = Array.from(new TextEncoder().encode(key));

    let xorBytes = textBytes.map((b, i) => b ^ keyBytes[i % keyBytes.length]);
    let hexOut = xorBytes.map(b => b.toString(16).padStart(2, '0')).join(' ');

    let charOut = '';
    xorBytes.forEach(b => {
        charOut += (b >= 32 && b <= 126) ? String.fromCharCode(b) : '·';
    });

    let result = `Raw XOR Output (ASCII / Printable):\n${charOut}\n\nHex Bytes:\n${hexOut}`;
    ctfToolkit.formatOutput(document.getElementById('xorOutput'), result);
    ctfToolkit.toggleOutput('xorOutputSection', true);
}

function xorBruteForceSingleByte() {
    const input = document.getElementById('xorInput').value.trim();
    if (!input) {
        ctfToolkit.showToast('Please enter text or hex to XOR brute force', 'error');
        return;
    }

    let bytes = [];
    const isHex = /^[0-9a-fA-F\s]+$/.test(input) && input.replace(/\s/g, '').length % 2 === 0;

    if (isHex && input.includes(' ')) {
        const clean = input.replace(/\s/g, '');
        for (let i = 0; i < clean.length; i += 2) {
            bytes.push(parseInt(clean.substr(i, 2), 16));
        }
    } else {
        bytes = Array.from(new TextEncoder().encode(input));
    }

    let results = [];
    for (let k = 0; k < 256; k++) {
        let decoded = '';
        let printable = 0;
        for (let b of bytes) {
            let x = b ^ k;
            if (x >= 32 && x <= 126) {
                printable++;
                decoded += String.fromCharCode(x);
            } else {
                decoded += '·';
            }
        }
        const score = (printable / bytes.length) * 100;
        if (score >= 60 || decoded.toLowerCase().includes('flag') || decoded.toLowerCase().includes('ctf')) {
            results.push(`Key 0x${k.toString(16).padStart(2, '0')} (${k.toString().padStart(3, ' ')}): ${decoded}`);
        }
    }

    if (results.length === 0) {
        results.push('No high-probability printable strings found across all 256 keys.');
    }

    ctfToolkit.formatOutput(document.getElementById('xorOutput'), results.join('\n'));
    ctfToolkit.toggleOutput('xorOutputSection', true);
}
