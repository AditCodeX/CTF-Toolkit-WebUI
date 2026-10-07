// Utility tools for CTF Toolkit

// Text Case Converter
function convertCase(caseType) {
    const input = document.getElementById('caseInput').value;
    
    if (!input) {
        ctfToolkit.showToast('Please enter some text to convert', 'error');
        return;
    }
    
    let result = '';
    
    // Split text into words handling camelCase, snake_case, kebab-case, and spaces
    const words = input
        .replace(/([a-z])([A-Z])/g, '$1 $2')
        .replace(/[_\-]+/g, ' ')
        .trim()
        .split(/\s+/);

    switch (caseType) {
        case 'upper':
            result = input.toUpperCase();
            break;
        case 'lower':
            result = input.toLowerCase();
            break;
        case 'title':
            result = words
                .map(w => w.charAt(0).toUpperCase() + w.slice(1).toLowerCase())
                .join(' ');
            break;
        case 'camel':
            result = words
                .map((w, i) => i === 0 ? w.toLowerCase() : w.charAt(0).toUpperCase() + w.slice(1).toLowerCase())
                .join('');
            break;
        case 'snake':
            result = words.map(w => w.toLowerCase()).join('_');
            break;
        case 'kebab':
            result = words.map(w => w.toLowerCase()).join('-');
            break;
        case 'constant':
            result = words.map(w => w.toUpperCase()).join('_');
            break;
    }
    
    ctfToolkit.formatOutput(document.getElementById('caseOutput'), result);
    ctfToolkit.toggleOutput('caseOutputSection', true);
}

// Text Reversal Functions
function reverseText() {
    const input = document.getElementById('reverseInput').value;
    if (!input) {
        ctfToolkit.showToast('Please enter some text to reverse', 'error');
        return;
    }
    const result = input.split('').reverse().join('');
    ctfToolkit.formatOutput(document.getElementById('reverseOutput'), result);
    ctfToolkit.toggleOutput('reverseOutputSection', true);
}

function reverseWords() {
    const input = document.getElementById('reverseInput').value;
    if (!input) {
        ctfToolkit.showToast('Please enter some text to reverse', 'error');
        return;
    }
    const result = input.split(/\s+/).reverse().join(' ');
    ctfToolkit.formatOutput(document.getElementById('reverseOutput'), result);
    ctfToolkit.toggleOutput('reverseOutputSection', true);
}

function reverseLines() {
    const input = document.getElementById('reverseInput').value;
    if (!input) {
        ctfToolkit.showToast('Please enter some text to reverse', 'error');
        return;
    }
    const result = input.split('\n').reverse().join('\n');
    ctfToolkit.formatOutput(document.getElementById('reverseOutput'), result);
    ctfToolkit.toggleOutput('reverseOutputSection', true);
}

// Character/Word Counter with UTF-8 byte measurement
function updateCounter() {
    const input = document.getElementById('counterInput').value;
    
    document.getElementById('charCount').textContent = input.length;
    document.getElementById('charCountNoSpace').textContent = input.replace(/\s/g, '').length;
    
    const words = input.trim().split(/\s+/).filter(word => word.length > 0);
    document.getElementById('wordCount').textContent = words.length;
    
    const lines = input.length === 0 ? 0 : input.split('\n').length;
    document.getElementById('lineCount').textContent = lines;
    
    const paragraphs = input.split(/\n\s*\n/).filter(para => para.trim().length > 0);
    document.getElementById('paragraphCount').textContent = paragraphs.length;

    const byteLength = new TextEncoder().encode(input).length;
    const byteEl = document.getElementById('byteCount');
    if (byteEl) {
        byteEl.textContent = byteLength;
    }
}

function clearCounter() {
    document.getElementById('counterInput').value = '';
    updateCounter();
}

// File Magic Bytes / Header Signature Identifier
const FILE_SIGNATURES = [
    { name: 'PNG Image', hex: '89504E470D0A1A0A', ext: '.png', desc: 'Portable Network Graphics' },
    { name: 'JPEG Image', hex: 'FFD8FF', ext: '.jpg / .jpeg', desc: 'Joint Photographic Experts Group' },
    { name: 'GIF87a Image', hex: '474946383761', ext: '.gif', desc: 'Graphics Interchange Format 87a' },
    { name: 'GIF89a Image', hex: '474946383961', ext: '.gif', desc: 'Graphics Interchange Format 89a' },
    { name: 'ZIP / DOCX / APK', hex: '504B0304', ext: '.zip / .docx / .apk', desc: 'ZIP Archive or OpenXML file' },
    { name: 'ZIP Empty Archive', hex: '504B0506', ext: '.zip', desc: 'Empty ZIP Archive' },
    { name: 'PDF Document', hex: '25504446', ext: '.pdf', desc: 'Adobe Portable Document Format' },
    { name: 'Linux ELF Executable', hex: '7F454C46', ext: '.elf / binary', desc: 'Executable and Linkable Format' },
    { name: 'Windows PE (EXE / DLL)', hex: '4D5A', ext: '.exe / .dll', desc: 'DOS MZ / Portable Executable' },
    { name: 'Wireshark PCAP (Big-Endian)', hex: 'A1B2C3D4', ext: '.pcap', desc: 'Libpcap Packet Capture' },
    { name: 'Wireshark PCAP (Little-Endian)', hex: 'D4C3B2A1', ext: '.pcap', desc: 'Libpcap Packet Capture' },
    { name: 'Wireshark PCAPNG', hex: '0A0D0D0A', ext: '.pcapng', desc: 'Pcap-NG Capture File' },
    { name: '7-Zip Archive', hex: '377ABCAF271C', ext: '.7z', desc: '7-Zip Compressed File' },
    { name: 'GZIP Compressed File', hex: '1F8B08', ext: '.gz', desc: 'GNU Zip Archive' },
    { name: 'BZIP2 Compressed File', hex: '425A68', ext: '.bz2', desc: 'Bzip2 Compressed Archive' },
    { name: 'TAR Archive', hex: '7573746172', ext: '.tar', desc: 'POSIX Tar Archive (ustar)' },
    { name: 'SQLite 3 Database', hex: '53514C69746520666F726D61742033', ext: '.db / .sqlite', desc: 'SQLite 3 Format' },
    { name: 'Java Class File', hex: 'CAFEBABE', ext: '.class', desc: 'Compiled Java Bytecode' },
    { name: 'WAV Audio', hex: '52494646', ext: '.wav', desc: 'RIFF Resource File' },
    { name: 'MP3 Audio (ID3)', hex: '494433', ext: '.mp3', desc: 'MP3 with ID3v2 tag' }
];

function identifyMagicBytes() {
    const input = document.getElementById('magicInput').value.trim();
    if (!input) {
        ctfToolkit.showToast('Please enter hex bytes to check magic signature', 'error');
        return;
    }

    const clean = input
        .replace(/\s+/g, '')
        .replace(/0x/gi, '')
        .replace(/\\x/gi, '')
        .toUpperCase();

    const matches = FILE_SIGNATURES.filter(sig => clean.startsWith(sig.hex));
    const output = document.getElementById('magicOutput');

    if (matches.length > 0) {
        let text = 'Matching File Signatures Found:\n\n';
        matches.forEach(m => {
            text += `[Format]:      ${m.name} (${m.ext})\n[Magic Hex]:   ${m.hex.match(/.{1,2}/g).join(' ')}\n[Description]: ${m.desc}\n\n`;
        });
        ctfToolkit.formatOutput(output, text.trim());
    } else {
        ctfToolkit.formatOutput(output, `Input Header: ${clean.slice(0, 32)}\nNo standard file magic bytes matched. Check offset or file integrity.`, true);
    }

    ctfToolkit.toggleOutput('magicOutputSection', true);
}

// CTF Flag Extractor
function extractFlags() {
    const text = document.getElementById('flagExtractorInput').value;
    const prefix = document.getElementById('flagPrefix').value.trim() || 'flag';

    if (!text) {
        ctfToolkit.showToast('Please enter text to search for flags', 'error');
        return;
    }

    // Escape regex characters in custom prefix
    const escapedPrefix = prefix.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const regex = new RegExp(`(?:${escapedPrefix})\\{[^\\r\\n\\}]+?\\}`, 'gi');
    
    const matches = text.match(regex);
    const output = document.getElementById('flagExtractorOutput');

    if (matches && matches.length > 0) {
        const unique = [...new Set(matches)];
        let res = `Found ${matches.length} flag(s) (${unique.length} unique):\n\n`;
        unique.forEach((f, idx) => {
            res += `[${idx + 1}] ${f}\n`;
        });
        ctfToolkit.formatOutput(output, res.trim());
    } else {
        ctfToolkit.formatOutput(output, `No flags matching "${prefix}{...}" pattern found in input.`, true);
    }

    ctfToolkit.toggleOutput('flagExtractorOutputSection', true);
}

// ASCII Table Reference Data
const asciiData = {
    control: [
        { dec: 0, hex: '00', oct: '000', char: 'NUL', desc: 'Null' },
        { dec: 1, hex: '01', oct: '001', char: 'SOH', desc: 'Start of Heading' },
        { dec: 2, hex: '02', oct: '002', char: 'STX', desc: 'Start of Text' },
        { dec: 3, hex: '03', oct: '003', char: 'ETX', desc: 'End of Text' },
        { dec: 4, hex: '04', oct: '004', char: 'EOT', desc: 'End of Transmission' },
        { dec: 5, hex: '05', oct: '005', char: 'ENQ', desc: 'Enquiry' },
        { dec: 6, hex: '06', oct: '006', char: 'ACK', desc: 'Acknowledge' },
        { dec: 7, hex: '07', oct: '007', char: 'BEL', desc: 'Bell' },
        { dec: 8, hex: '08', oct: '010', char: 'BS', desc: 'Backspace' },
        { dec: 9, hex: '09', oct: '011', char: 'TAB', desc: 'Horizontal Tab' },
        { dec: 10, hex: '0A', oct: '012', char: 'LF', desc: 'Line Feed' },
        { dec: 11, hex: '0B', oct: '013', char: 'VT', desc: 'Vertical Tab' },
        { dec: 12, hex: '0C', oct: '014', char: 'FF', desc: 'Form Feed' },
        { dec: 13, hex: '0D', oct: '015', char: 'CR', desc: 'Carriage Return' },
        { dec: 14, hex: '0E', oct: '016', char: 'SO', desc: 'Shift Out' },
        { dec: 15, hex: '0F', oct: '017', char: 'SI', desc: 'Shift In' },
        { dec: 16, hex: '10', oct: '020', char: 'DLE', desc: 'Data Link Escape' },
        { dec: 17, hex: '11', oct: '021', char: 'DC1', desc: 'Device Control 1' },
        { dec: 18, hex: '12', oct: '022', char: 'DC2', desc: 'Device Control 2' },
        { dec: 19, hex: '13', oct: '023', char: 'DC3', desc: 'Device Control 3' },
        { dec: 20, hex: '14', oct: '024', char: 'DC4', desc: 'Device Control 4' },
        { dec: 21, hex: '15', oct: '025', char: 'NAK', desc: 'Negative Acknowledge' },
        { dec: 22, hex: '16', oct: '026', char: 'SYN', desc: 'Synchronous Idle' },
        { dec: 23, hex: '17', oct: '027', char: 'ETB', desc: 'End of Trans. Block' },
        { dec: 24, hex: '18', oct: '030', char: 'CAN', desc: 'Cancel' },
        { dec: 25, hex: '19', oct: '031', char: 'EM', desc: 'End of Medium' },
        { dec: 26, hex: '1A', oct: '032', char: 'SUB', desc: 'Substitute' },
        { dec: 27, hex: '1B', oct: '033', char: 'ESC', desc: 'Escape' },
        { dec: 28, hex: '1C', oct: '034', char: 'FS', desc: 'File Separator' },
        { dec: 29, hex: '1D', oct: '035', char: 'GS', desc: 'Group Separator' },
        { dec: 30, hex: '1E', oct: '036', char: 'RS', desc: 'Record Separator' },
        { dec: 31, hex: '1F', oct: '037', char: 'US', desc: 'Unit Separator' },
        { dec: 127, hex: '7F', oct: '177', char: 'DEL', desc: 'Delete' }
    ]
};

// Generate printable ASCII characters (32 - 126)
asciiData.printable = [];
for (let i = 32; i <= 126; i++) {
    asciiData.printable.push({
        dec: i,
        hex: i.toString(16).toUpperCase().padStart(2, '0'),
        oct: i.toString(8).padStart(3, '0'),
        char: String.fromCharCode(i),
        desc: getASCIIDescription(i)
    });
}

// Generate extended ASCII characters (128 - 255)
asciiData.extended = [];
for (let i = 128; i <= 255; i++) {
    asciiData.extended.push({
        dec: i,
        hex: i.toString(16).toUpperCase().padStart(2, '0'),
        oct: i.toString(8).padStart(3, '0'),
        char: String.fromCharCode(i),
        desc: 'Extended ASCII'
    });
}

function getASCIIDescription(code) {
    const descriptions = {
        32: 'Space',
        33: 'Exclamation mark',
        34: 'Double quotes',
        35: 'Number sign / Hash',
        36: 'Dollar sign',
        37: 'Percent sign',
        38: 'Ampersand',
        39: 'Single quote',
        40: 'Opening parenthesis',
        41: 'Closing parenthesis',
        42: 'Asterisk',
        43: 'Plus sign',
        44: 'Comma',
        45: 'Hyphen / Minus',
        46: 'Period / Dot',
        47: 'Slash',
        58: 'Colon',
        59: 'Semicolon',
        60: 'Less than',
        61: 'Equal sign',
        62: 'Greater than',
        63: 'Question mark',
        64: 'At symbol',
        91: 'Opening bracket',
        92: 'Backslash',
        93: 'Closing bracket',
        94: 'Caret',
        95: 'Underscore',
        96: 'Grave accent / Backtick',
        123: 'Opening brace',
        124: 'Vertical bar / Pipe',
        125: 'Closing brace',
        126: 'Tilde'
    };
    
    if (descriptions[code]) return descriptions[code];
    if (code >= 48 && code <= 57) return 'Digit ' + String.fromCharCode(code);
    if (code >= 65 && code <= 90) return 'Uppercase ' + String.fromCharCode(code);
    if (code >= 97 && code <= 122) return 'Lowercase ' + String.fromCharCode(code);
    return '';
}

let currentASCIIRange = 'printable';

function showASCIIRange(range) {
    currentASCIIRange = range;
    filterASCIITable();
}

function filterASCIITable() {
    const tbody = document.getElementById('asciiTableBody');
    if (!tbody) return;
    tbody.innerHTML = '';
    
    const searchInput = document.getElementById('asciiSearchInput');
    const query = searchInput ? searchInput.value.trim().toLowerCase() : '';

    let data = [];
    if (query) {
        // When searching, search across all ASCII character categories
        data = [...asciiData.control, ...asciiData.printable, ...asciiData.extended];
        data.sort((a, b) => a.dec - b.dec);
        data = data.filter(item => 
            (item.dec !== undefined && item.dec.toString().includes(query)) ||
            (item.hex && item.hex.toLowerCase().includes(query)) ||
            (item.oct && item.oct.includes(query)) ||
            (item.char && item.char.toLowerCase().includes(query)) ||
            (item.desc && item.desc.toLowerCase().includes(query))
        );
    } else {
        switch (currentASCIIRange) {
            case 'control':
                data = asciiData.control;
                break;
            case 'printable':
                data = asciiData.printable;
                break;
            case 'extended':
                data = asciiData.extended;
                break;
            case 'all':
                data = [...asciiData.control, ...asciiData.printable, ...asciiData.extended];
                data.sort((a, b) => a.dec - b.dec);
                break;
        }
    }

    const fragment = document.createDocumentFragment();
    data.forEach(item => {
        const row = document.createElement('tr');
        
        const tdDec = document.createElement('td');
        tdDec.textContent = item.dec;
        
        const tdHex = document.createElement('td');
        tdHex.textContent = '0x' + item.hex;
        
        const tdOct = document.createElement('td');
        tdOct.textContent = item.oct;
        
        const tdChar = document.createElement('td');
        tdChar.textContent = item.char; // Safe escaping for <, >, &, etc.
        
        const tdDesc = document.createElement('td');
        tdDesc.textContent = item.desc;
        
        row.appendChild(tdDec);
        row.appendChild(tdHex);
        row.appendChild(tdOct);
        row.appendChild(tdChar);
        row.appendChild(tdDesc);
        
        fragment.appendChild(row);
    });

    tbody.appendChild(fragment);
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    if (document.getElementById('asciiTableBody')) {
        showASCIIRange('printable');
    }
});
