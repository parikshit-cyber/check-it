/**
 * Network Scanner Engine
 * DNS leak testing, port scan simulation, SSL/TLS analysis, latency testing
 */

const https = require('https');
const http = require('http');
const { URL } = require('url');
const dns = require('dns');
const tls = require('tls');

/**
 * DNS Leak Test — resolve a domain through multiple DNS perspectives
 */
async function dnsLeakTest(domain = 'example.com') {
    const results = [];

    // Test system DNS resolution
    try {
        const addresses = await new Promise((resolve, reject) => {
            dns.resolve4(domain, (err, addrs) => {
                if (err) reject(err);
                else resolve(addrs);
            });
        });
        results.push({
            resolver: 'System DNS',
            domain,
            ips: addresses,
            status: 'ok',
        });
    } catch (err) {
        results.push({
            resolver: 'System DNS',
            domain,
            ips: [],
            status: 'failed',
            error: err.message,
        });
    }

    // Check via public DNS APIs
    const dnsAPIs = [
        { name: 'Cloudflare (1.1.1.1)', url: `https://cloudflare-dns.com/dns-query?name=${domain}&type=A` },
        { name: 'Google (8.8.8.8)', url: `https://dns.google/resolve?name=${domain}&type=A` },
    ];

    for (const api of dnsAPIs) {
        try {
            const data = await fetchJSON(api.url, { 'Accept': 'application/dns-json' });
            const ips = (data.Answer || []).filter((a) => a.type === 1).map((a) => a.data);
            results.push({ resolver: api.name, domain, ips, status: 'ok' });
        } catch {
            results.push({ resolver: api.name, domain, ips: [], status: 'failed' });
        }
    }

    // Analyze for leaks
    const allIPs = new Set(results.flatMap((r) => r.ips));
    const hasLeak = results.filter((r) => r.status === 'ok').length > 1 &&
        new Set(results.filter((r) => r.status === 'ok').map((r) => JSON.stringify(r.ips.sort()))).size > 1;

    return {
        domain,
        resolvers: results,
        uniqueIPs: [...allIPs],
        potentialLeak: hasLeak,
        leakDescription: hasLeak
            ? 'Different DNS resolvers returned different IPs — your DNS queries may be leaking to third parties.'
            : 'All resolvers returned consistent results — no DNS leak detected.',
        timestamp: new Date().toISOString(),
    };
}

/**
 * Port Scan Simulation — simulates scanning common ports
 */
async function portScan(target = 'localhost') {
    const commonPorts = [
        { port: 21, service: 'FTP', risk: 'high', description: 'File Transfer Protocol — often unencrypted' },
        { port: 22, service: 'SSH', risk: 'medium', description: 'Secure Shell — remote access' },
        { port: 23, service: 'Telnet', risk: 'critical', description: 'Unencrypted remote access — extremely dangerous' },
        { port: 25, service: 'SMTP', risk: 'medium', description: 'Email sending — can be used for spam relay' },
        { port: 53, service: 'DNS', risk: 'low', description: 'Domain Name System — normal if intentional' },
        { port: 80, service: 'HTTP', risk: 'low', description: 'Web server — unencrypted web traffic' },
        { port: 110, service: 'POP3', risk: 'high', description: 'Email retrieval — often unencrypted' },
        { port: 135, service: 'RPC', risk: 'critical', description: 'Windows RPC — frequently exploited' },
        { port: 139, service: 'NetBIOS', risk: 'critical', description: 'Windows file sharing — highly exploitable' },
        { port: 443, service: 'HTTPS', risk: 'low', description: 'Encrypted web traffic — normal' },
        { port: 445, service: 'SMB', risk: 'critical', description: 'Windows file sharing — ransomware vector' },
        { port: 993, service: 'IMAPS', risk: 'low', description: 'Encrypted email access' },
        { port: 1433, service: 'MSSQL', risk: 'high', description: 'Microsoft SQL Server — should not be public' },
        { port: 3306, service: 'MySQL', risk: 'high', description: 'MySQL database — should not be public' },
        { port: 3389, service: 'RDP', risk: 'critical', description: 'Remote Desktop — brute force target' },
        { port: 5432, service: 'PostgreSQL', risk: 'high', description: 'PostgreSQL database — should not be public' },
        { port: 5900, service: 'VNC', risk: 'critical', description: 'Remote desktop — often weakly secured' },
        { port: 6379, service: 'Redis', risk: 'critical', description: 'Redis database — never expose publicly' },
        { port: 8080, service: 'HTTP-Alt', risk: 'medium', description: 'Alternative web server' },
        { port: 8443, service: 'HTTPS-Alt', risk: 'low', description: 'Alternative secure web server' },
        { port: 27017, service: 'MongoDB', risk: 'critical', description: 'MongoDB — massive data breach vector' },
    ];

    // Simulate scan results with realistic randomization
    const results = commonPorts.map((p) => {
        // Simulate: most ports closed, some open
        const rng = Math.random();
        let status;
        if (p.port === 80 || p.port === 443) {
            status = 'open'; // Web ports usually open
        } else if (p.risk === 'critical' && rng > 0.92) {
            status = 'open';
        } else if (p.risk === 'high' && rng > 0.88) {
            status = 'open';
        } else if (rng > 0.85) {
            status = 'filtered';
        } else {
            status = 'closed';
        }
        return { ...p, status };
    });

    const openPorts = results.filter((r) => r.status === 'open');
    const filteredPorts = results.filter((r) => r.status === 'filtered');
    const criticalOpen = openPorts.filter((p) => p.risk === 'critical');

    let riskLevel;
    if (criticalOpen.length > 0) riskLevel = 'critical';
    else if (openPorts.filter((p) => p.risk === 'high').length > 0) riskLevel = 'high';
    else if (openPorts.length > 5) riskLevel = 'medium';
    else riskLevel = 'low';

    return {
        target,
        results,
        summary: {
            open: openPorts.length,
            closed: results.filter((r) => r.status === 'closed').length,
            filtered: filteredPorts.length,
            total: results.length,
            riskLevel,
            criticalFindings: criticalOpen.length,
        },
        timestamp: new Date().toISOString(),
    };
}

/**
 * SSL/TLS Certificate Analysis
 */
function sslCheck(hostname) {
    return new Promise((resolve) => {
        try {
            const options = {
                host: hostname,
                port: 443,
                servername: hostname,
                rejectUnauthorized: false,
                timeout: 8000,
            };

            const socket = tls.connect(options, () => {
                const cert = socket.getPeerCertificate(true);
                const protocol = socket.getProtocol();
                const cipher = socket.getCipher();
                const authorized = socket.authorized;

                if (!cert || !cert.subject) {
                    socket.destroy();
                    resolve({ error: 'No certificate returned', hostname });
                    return;
                }

                const now = new Date();
                const validFrom = new Date(cert.valid_from);
                const validTo = new Date(cert.valid_to);
                const daysRemaining = Math.ceil((validTo - now) / (1000 * 60 * 60 * 24));
                const isExpired = daysRemaining < 0;
                const isExpiringSoon = daysRemaining > 0 && daysRemaining < 30;

                const findings = [];
                if (isExpired) findings.push({ severity: 'critical', message: 'Certificate has EXPIRED' });
                if (isExpiringSoon) findings.push({ severity: 'warning', message: `Certificate expires in ${daysRemaining} days` });
                if (!authorized) findings.push({ severity: 'warning', message: 'Certificate not fully trusted by system CA' });
                if (protocol === 'TLSv1' || protocol === 'TLSv1.1') findings.push({ severity: 'critical', message: `Outdated protocol: ${protocol}` });
                if (cert.subject.CN && !cert.subject.CN.includes(hostname) && !(cert.subjectaltname || '').includes(hostname)) {
                    findings.push({ severity: 'warning', message: 'Hostname mismatch with certificate CN/SAN' });
                }

                let grade;
                if (isExpired) grade = 'F';
                else if (findings.filter((f) => f.severity === 'critical').length > 0) grade = 'D';
                else if (findings.filter((f) => f.severity === 'warning').length > 1) grade = 'C';
                else if (findings.length > 0) grade = 'B';
                else grade = 'A';

                socket.destroy();
                resolve({
                    hostname,
                    grade,
                    protocol,
                    cipher: cipher ? { name: cipher.name, version: cipher.version } : null,
                    certificate: {
                        subject: cert.subject,
                        issuer: cert.issuer,
                        validFrom: validFrom.toISOString(),
                        validTo: validTo.toISOString(),
                        daysRemaining,
                        isExpired,
                        serialNumber: cert.serialNumber,
                        fingerprint: cert.fingerprint256 || cert.fingerprint,
                        san: cert.subjectaltname || 'None',
                    },
                    authorized,
                    findings,
                    timestamp: new Date().toISOString(),
                });
            });

            socket.on('error', (err) => {
                resolve({ error: err.message, hostname });
            });
            socket.on('timeout', () => {
                socket.destroy();
                resolve({ error: 'Connection timed out', hostname });
            });
        } catch (err) {
            resolve({ error: err.message, hostname });
        }
    });
}

/**
 * Latency test to global endpoints
 */
async function latencyTest() {
    const endpoints = [
        { name: 'Cloudflare', url: 'https://1.1.1.1/cdn-cgi/trace', region: 'Global CDN', lat: 37.7749, lng: -122.4194 },
        { name: 'Google', url: 'https://www.google.com/generate_204', region: 'US West', lat: 37.386, lng: -122.084 },
        { name: 'Amazon AWS', url: 'https://aws.amazon.com/ping', region: 'US East', lat: 39.0438, lng: -77.4874 },
        { name: 'Microsoft Azure', url: 'https://azure.microsoft.com', region: 'US Central', lat: 41.8819, lng: -93.0977 },
        { name: 'Hetzner', url: 'https://www.hetzner.com', region: 'EU Germany', lat: 50.1109, lng: 8.6821 },
        { name: 'DigitalOcean', url: 'https://www.digitalocean.com', region: 'US East', lat: 40.7128, lng: -74.006 },
        { name: 'OVH', url: 'https://www.ovh.com', region: 'EU France', lat: 50.6292, lng: 3.0573 },
        { name: 'Linode', url: 'https://www.linode.com', region: 'US East', lat: 39.9526, lng: -75.1652 },
    ];

    const results = [];
    for (const ep of endpoints) {
        const start = Date.now();
        try {
            await new Promise((resolve, reject) => {
                const req = https.get(ep.url, { timeout: 5000 }, (res) => {
                    res.on('data', () => { });
                    res.on('end', resolve);
                });
                req.on('error', reject);
                req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
            });
            const latency = Date.now() - start;
            results.push({ ...ep, latency, status: 'ok' });
        } catch {
            results.push({ ...ep, latency: null, status: 'timeout' });
        }
    }

    results.sort((a, b) => (a.latency || 9999) - (b.latency || 9999));

    const validLatencies = results.filter((r) => r.latency !== null);
    const avgLatency = validLatencies.length
        ? Math.round(validLatencies.reduce((s, r) => s + r.latency, 0) / validLatencies.length)
        : null;

    return {
        results,
        average: avgLatency,
        fastest: validLatencies[0] || null,
        slowest: validLatencies[validLatencies.length - 1] || null,
        timestamp: new Date().toISOString(),
    };
}

/**
 * Helper: fetch JSON with custom headers
 */
function fetchJSON(url, headers = {}) {
    return new Promise((resolve, reject) => {
        const u = new URL(url);
        const mod = u.protocol === 'https:' ? https : http;
        mod.get(url, { timeout: 5000, headers }, (res) => {
            let data = '';
            res.on('data', (c) => (data += c));
            res.on('end', () => {
                try { resolve(JSON.parse(data)); }
                catch { reject(new Error('Invalid JSON')); }
            });
        }).on('error', reject).on('timeout', function () { this.destroy(); reject(new Error('Timeout')); });
    });
}

module.exports = { dnsLeakTest, portScan, sslCheck, latencyTest };
