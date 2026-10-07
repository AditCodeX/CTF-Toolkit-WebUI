// Encoding/Decoding tools for CTF Toolkit

// RFC 4648 Base32 Alphabet
const RFC4648_BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

// Base64 Encoding/Decoding with Base64URL and UTF-8 / Binary support
function base64Encode(urlSafe = false) {
    const input = document.getElementById('base64Input').value;
    
    if (!input) {
        ctfToolkit.showToast('Please enter some text to encode', 'error');
        return;
    }
    
    try {
        const bytes = new TextEncoder().encode(input);
        let binaryStr = '';
        for (let i = 0; i < bytes.length; i++) {
            binaryStr += String.fromCharCode(bytes[i]);
        }
        let encoded = btoa(binaryStr);
        if (urlSafe) {
            encoded = encoded.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
        }
        ctfToolkit.formatOutput(document.getElementById('base64Output'), encoded);
        ctfToolkit.toggleOutput('base64OutputSection', true);
    } catch (error) {
        ctfToolkit.formatOutput(document.getElementById('base64Output'), 'Error encoding: ' + error.message, true);
        ctfToolkit.toggleOutput('base64OutputSection', true);
    }
}

function base64Decode() {
    const input = document.getElementById('base64Input').value;
    
    if (!input) {
        ctfToolkit.showToast('Please enter a Base64 string to decode', 'error');
        return;
    }
    
    try {
        let clean = input.trim().replace(/\s/g, '').replace(/-/g, '+').replace(/_/g, '/');
        while (clean.length % 4 !== 0) {
            clean += '=';
        }

        const binStr = atob(clean);
        const bytes = new Uint8Array(binStr.length);
        for (let i = 0; i < binStr.length; i++) {
            bytes[i] = binStr.charCodeAt(i);
        }

        let decoded;
        try {
            decoded = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
        } catch (e) {
            // Binary fallback with hex preview
            const hex = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join(' ');
            decoded = `[Binary Payload Detected - Hex Representation]:\n${hex}`;
        }

        ctfToolkit.formatOutput(document.getElementById('base64Output'), decoded);
        ctfToolkit.toggleOutput('base64OutputSection', true);
    } catch (error) {
        ctfToolkit.formatOutput(document.getElementById('base64Output'), 'Error decoding: ' + error.message, true);
        ctfToolkit.toggleOutput('base64OutputSection', true);
    }
}

// Base32 RFC 4648
function base32Encode(textInput) {
    const input = textInput !== undefined ? textInput : (document.getElementById('base32Input') ? document.getElementById('base32Input').value : '');
    if (!input) {
        if (textInput === undefined) ctfToolkit.showToast('Please enter text to encode to Base32', 'error');
        return '';
    }

    try {
        const bytes = new TextEncoder().encode(input);
        let bits = 0;
        let value = 0;
        let output = '';
        for (let i = 0; i < bytes.length; i++) {
            value = (value << 8) | bytes[i];
            bits += 8;
            while (bits >= 5) {
                output += RFC4648_BASE32[(value >>> (bits - 5)) & 31];
                bits -= 5;
            }
        }
        if (bits > 0) {
            output += RFC4648_BASE32[(value << (5 - bits)) & 31];
        }
        while (output.length % 8 !== 0) {
            output += '=';
        }
        if (textInput === undefined) {
            ctfToolkit.formatOutput(document.getElementById('base32Output'), output);
            ctfToolkit.toggleOutput('base32OutputSection', true);
        }
        return output;
    } catch (err) {
        if (textInput === undefined) {
            ctfToolkit.formatOutput(document.getElementById('base32Output'), 'Error: ' + err.message, true);
            ctfToolkit.toggleOutput('base32OutputSection', true);
        }
        throw err;
    }
}

function base32Decode(textInput) {
    const input = textInput !== undefined ? textInput : (document.getElementById('base32Input') ? document.getElementById('base32Input').value : '');
    if (!input) {
        if (textInput === undefined) ctfToolkit.showToast('Please enter Base32 string to decode', 'error');
        return '';
    }

    try {
        const clean = input.replace(/=+$/, '').toUpperCase().replace(/\s/g, '');
        let bits = 0;
        let value = 0;
        const bytes = [];
        for (let i = 0; i < clean.length; i++) {
            const val = RFC4648_BASE32.indexOf(clean[i]);
            if (val === -1) throw new Error('Invalid Base32 character: ' + clean[i]);
            value = (value << 5) | val;
            bits += 5;
            if (bits >= 8) {
                bytes.push((value >>> (bits - 8)) & 255);
                bits -= 8;
            }
        }
        const decoded = new TextDecoder('utf-8').decode(new Uint8Array(bytes));
        if (textInput === undefined) {
            ctfToolkit.formatOutput(document.getElementById('base32Output'), decoded);
            ctfToolkit.toggleOutput('base32OutputSection', true);
        }
        return decoded;
    } catch (err) {
        if (textInput === undefined) {
            ctfToolkit.formatOutput(document.getElementById('base32Output'), 'Error: ' + err.message, true);
            ctfToolkit.toggleOutput('base32OutputSection', true);
        }
        throw err;
    }
}

// URL Encoding/Decoding (Standard + Full WAF Bypass Encoding)
function urlEncode(full = false) {
    const input = document.getElementById('urlInput').value;
    
    if (!input) {
        ctfToolkit.showToast('Please enter some text to encode', 'error');
        return;
    }
    
    try {
        let encoded;
        if (full) {
            // Full URL encode: every character into %XX
            const bytes = new TextEncoder().encode(input);
            encoded = Array.from(bytes).map(b => '%' + b.toString(16).toUpperCase().padStart(2, '0')).join('');
        } else {
            encoded = encodeURIComponent(input);
        }
        ctfToolkit.formatOutput(document.getElementById('urlOutput'), encoded);
        ctfToolkit.toggleOutput('urlOutputSection', true);
    } catch (error) {
        ctfToolkit.formatOutput(document.getElementById('urlOutput'), 'Error encoding: ' + error.message, true);
        ctfToolkit.toggleOutput('urlOutputSection', true);
    }
}

function urlDecode() {
    const input = document.getElementById('urlInput').value;
    
    if (!input) {
        ctfToolkit.showToast('Please enter a URL-encoded string to decode', 'error');
        return;
    }
    
    try {
        const decoded = decodeURIComponent(input);
        ctfToolkit.formatOutput(document.getElementById('urlOutput'), decoded);
        ctfToolkit.toggleOutput('urlOutputSection', true);
    } catch (error) {
        ctfToolkit.formatOutput(document.getElementById('urlOutput'), 'Error decoding: Invalid URL-encoded string', true);
        ctfToolkit.toggleOutput('urlOutputSection', true);
    }
}

// Hex to ASCII and vice versa
function hexToAscii() {
    const input = document.getElementById('hexInput').value.trim();
    
    if (!input) {
        ctfToolkit.showToast('Please enter a hex string', 'error');
        return;
    }
    
    try {
        // Remove spaces, 0x, \x, and colons
        let cleanHex = input
            .replace(/\s+/g, '')
            .replace(/\\x/gi, '')
            .replace(/0x/gi, '')
            .replace(/:/g, '');
        
        if (cleanHex.length % 2 !== 0) {
            cleanHex = '0' + cleanHex;
        }

        if (!/^[0-9A-Fa-f]*$/.test(cleanHex)) {
            throw new Error('Input contains non-hexadecimal characters');
        }
        
        const bytes = new Uint8Array(cleanHex.length / 2);
        for (let i = 0; i < cleanHex.length; i += 2) {
            bytes[i / 2] = parseInt(cleanHex.substr(i, 2), 16);
        }

        let ascii;
        try {
            ascii = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
        } catch (e) {
            ascii = Array.from(bytes).map(b => (b >= 32 && b <= 126) ? String.fromCharCode(b) : '·').join('');
        }
        
        ctfToolkit.formatOutput(document.getElementById('hexOutput'), ascii);
        ctfToolkit.toggleOutput('hexOutputSection', true);
    } catch (error) {
        ctfToolkit.formatOutput(document.getElementById('hexOutput'), 'Error converting: ' + error.message, true);
        ctfToolkit.toggleOutput('hexOutputSection', true);
    }
}

function asciiToHex(format = 'spaced') {
    const input = document.getElementById('hexInput').value;
    
    if (!input) {
        ctfToolkit.showToast('Please enter some text', 'error');
        return;
    }
    
    try {
        const bytes = new TextEncoder().encode(input);
        let hexArray = Array.from(bytes).map(b => b.toString(16).padStart(2, '0'));
        
        let formattedHex;
        if (format === 'escaped') {
            formattedHex = hexArray.map(h => '\\x' + h).join('');
        } else if (format === 'continuous') {
            formattedHex = hexArray.join('');
        } else {
            formattedHex = hexArray.join(' ');
        }
        
        ctfToolkit.formatOutput(document.getElementById('hexOutput'), formattedHex);
        ctfToolkit.toggleOutput('hexOutputSection', true);
    } catch (error) {
        ctfToolkit.formatOutput(document.getElementById('hexOutput'), 'Error converting: ' + error.message, true);
        ctfToolkit.toggleOutput('hexOutputSection', true);
    }
}

// Binary to Text and vice versa
function binaryToText() {
    const input = document.getElementById('binaryInput').value.trim();
    
    if (!input) {
        ctfToolkit.showToast('Please enter a binary string', 'error');
        return;
    }
    
    try {
        const cleanBinary = input.replace(/\s/g, '');
        
        if (!/^[01]*$/.test(cleanBinary)) {
            throw new Error('Invalid binary string (only 0 and 1 allowed)');
        }
        
        const bytes = [];
        for (let i = 0; i < cleanBinary.length; i += 8) {
            const byte = cleanBinary.substr(i, 8);
            if (byte.length === 8) {
                bytes.push(parseInt(byte, 2));
            }
        }
        
        const text = new TextDecoder('utf-8').decode(new Uint8Array(bytes));
        ctfToolkit.formatOutput(document.getElementById('binaryOutput'), text);
        ctfToolkit.toggleOutput('binaryOutputSection', true);
    } catch (error) {
        ctfToolkit.formatOutput(document.getElementById('binaryOutput'), 'Error converting: ' + error.message, true);
        ctfToolkit.toggleOutput('binaryOutputSection', true);
    }
}

function textToBinary() {
    const input = document.getElementById('binaryInput').value;
    
    if (!input) {
        ctfToolkit.showToast('Please enter some text', 'error');
        return;
    }
    
    try {
        const bytes = new TextEncoder().encode(input);
        const binary = Array.from(bytes).map(b => b.toString(2).padStart(8, '0')).join(' ');
        
        ctfToolkit.formatOutput(document.getElementById('binaryOutput'), binary);
        ctfToolkit.toggleOutput('binaryOutputSection', true);
    } catch (error) {
        ctfToolkit.formatOutput(document.getElementById('binaryOutput'), 'Error converting: ' + error.message, true);
        ctfToolkit.toggleOutput('binaryOutputSection', true);
    }
}

// HTML Entity Encoding/Decoding
function htmlEncode() {
    const input = document.getElementById('htmlInput').value;
    
    if (!input) {
        ctfToolkit.showToast('Please enter some text to encode', 'error');
        return;
    }
    
    try {
        const encoded = input
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
        
        ctfToolkit.formatOutput(document.getElementById('htmlOutput'), encoded);
        ctfToolkit.toggleOutput('htmlOutputSection', true);
    } catch (error) {
        ctfToolkit.formatOutput(document.getElementById('htmlOutput'), 'Error encoding: ' + error.message, true);
        ctfToolkit.toggleOutput('htmlOutputSection', true);
    }
}

function htmlDecode() {
    const input = document.getElementById('htmlInput').value;
    
    if (!input) {
        ctfToolkit.showToast('Please enter HTML-encoded text to decode', 'error');
        return;
    }
    
    try {
        const doc = new DOMParser().parseFromString(input, 'text/html');
        const decoded = doc.documentElement.textContent;
        
        ctfToolkit.formatOutput(document.getElementById('htmlOutput'), decoded);
        ctfToolkit.toggleOutput('htmlOutputSection', true);
    } catch (error) {
        ctfToolkit.formatOutput(document.getElementById('htmlOutput'), 'Error decoding: ' + error.message, true);
        ctfToolkit.toggleOutput('htmlOutputSection', true);
    }
}

// Morse Code
const MORSE_CODE_MAP = {
    'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.',
    'G': '--.', 'H': '....', 'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..',
    'M': '--', 'N': '-.', 'O': '---', 'P': '.--.', 'Q': '--.-', 'R': '.-.',
    'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-',
    'Y': '-.--', 'Z': '--..', '0': '-----', '1': '.----', '2': '..---',
    '3': '...--', '4': '....-', '5': '.....', '6': '-....', '7': '--...',
    '8': '---..', '9': '----.', ' ': '/'
};

const REVERSE_MORSE_MAP = {};
for (const [char, morse] of Object.entries(MORSE_CODE_MAP)) {
    REVERSE_MORSE_MAP[morse] = char;
}

function morseEncode() {
    const input = document.getElementById('morseInput').value;
    if (!input) {
        ctfToolkit.showToast('Please enter text to encode to Morse code', 'error');
        return;
    }

    const encoded = input.toUpperCase().split('').map(c => MORSE_CODE_MAP[c] || c).join(' ');
    ctfToolkit.formatOutput(document.getElementById('morseOutput'), encoded);
    ctfToolkit.toggleOutput('morseOutputSection', true);
}

function morseDecode() {
    const input = document.getElementById('morseInput').value;
    if (!input) {
        ctfToolkit.showToast('Please enter Morse code to decode', 'error');
        return;
    }

    const tokens = input.trim().split(/\s+/);
    const decoded = tokens.map(t => REVERSE_MORSE_MAP[t] || (t === '/' ? ' ' : t)).join('');
    ctfToolkit.formatOutput(document.getElementById('morseOutput'), decoded);
    ctfToolkit.toggleOutput('morseOutputSection', true);
}
