/**
 * Device Security Engine
 * Analyzes browser security headers and provides server-side security checks.
 * Most fingerprinting happens client-side; this handles header analysis.
 */

const http = require('http');
const https = require('https');

/**
 * Check security headers of a given URL
 */
function checkSecurityHeaders(url) {
    return new Promise((resolve) => {
        try {
            const mod = url.startsWith('https') ? https : http;
            const req = mod.get(url, { timeout: 8000 }, (res) => {
                const headers = res.headers;
                const checks = [];

                // Content-Security-Policy
                checks.push({
                    name: 'Content-Security-Policy',
                    present: !!headers['content-security-policy'],
                    value: headers['content-security-policy'] || null,
                    severity: 'high',
                    description: 'Prevents XSS, clickjacking, and code injection attacks',
                });

                // Strict-Transport-Security (HSTS)
                checks.push({
                    name: 'Strict-Transport-Security',
                    present: !!headers['strict-transport-security'],
                    value: headers['strict-transport-security'] || null,
                    severity: 'high',
                    description: 'Forces HTTPS connections, prevents downgrade attacks',
                });

                // X-Content-Type-Options
                checks.push({
                    name: 'X-Content-Type-Options',
                    present: !!headers['x-content-type-options'],
                    value: headers['x-content-type-options'] || null,
                    severity: 'medium',
                    description: 'Prevents MIME type sniffing attacks',
                });

                // X-Frame-Options
                checks.push({
                    name: 'X-Frame-Options',
                    present: !!headers['x-frame-options'],
                    value: headers['x-frame-options'] || null,
                    severity: 'medium',
                    description: 'Prevents clickjacking by controlling iframe embedding',
                });

                // X-XSS-Protection
                checks.push({
                    name: 'X-XSS-Protection',
                    present: !!headers['x-xss-protection'],
                    value: headers['x-xss-protection'] || null,
                    severity: 'low',
                    description: 'Legacy XSS filter (modern browsers use CSP instead)',
                });

                // Referrer-Policy
                checks.push({
                    name: 'Referrer-Policy',
                    present: !!headers['referrer-policy'],
                    value: headers['referrer-policy'] || null,
                    severity: 'medium',
                    description: 'Controls how much referrer information is shared',
                });

                // Permissions-Policy
                checks.push({
                    name: 'Permissions-Policy',
                    present: !!headers['permissions-policy'],
                    value: headers['permissions-policy'] || null,
                    severity: 'medium',
                    description: 'Controls which browser features can be used',
                });

                // X-DNS-Prefetch-Control
                checks.push({
                    name: 'X-DNS-Prefetch-Control',
                    present: !!headers['x-dns-prefetch-control'],
                    value: headers['x-dns-prefetch-control'] || null,
                    severity: 'low',
                    description: 'Controls DNS prefetching to prevent privacy leaks',
                });

                // Cache-Control
                checks.push({
                    name: 'Cache-Control',
                    present: !!headers['cache-control'],
                    value: headers['cache-control'] || null,
                    severity: 'low',
                    description: 'Controls caching behavior for sensitive content',
                });

                // Server header exposure
                checks.push({
                    name: 'Server Header Hidden',
                    present: !headers['server'],
                    value: headers['server'] || 'Not exposed',
                    severity: 'low',
                    description: 'Hiding server info prevents targeted attacks',
                });

                // X-Powered-By hidden
                checks.push({
                    name: 'X-Powered-By Hidden',
                    present: !headers['x-powered-by'],
                    value: headers['x-powered-by'] || 'Not exposed',
                    severity: 'low',
                    description: 'Hiding technology stack prevents targeted exploits',
                });

                const passed = checks.filter((c) => c.present).length;
                const total = checks.length;
                const score = Math.round((passed / total) * 100);

                let grade;
                if (score >= 90) grade = 'A+';
                else if (score >= 80) grade = 'A';
                else if (score >= 70) grade = 'B';
                else if (score >= 60) grade = 'C';
                else if (score >= 50) grade = 'D';
                else grade = 'F';

                resolve({
                    url,
                    score,
                    grade,
                    passed,
                    total,
                    checks,
                    statusCode: res.statusCode,
                    protocol: url.startsWith('https') ? 'HTTPS' : 'HTTP',
                    timestamp: new Date().toISOString(),
                });
            });

            req.on('error', () => {
                resolve({ error: 'Could not connect to the URL', url });
            });
            req.on('timeout', () => {
                req.destroy();
                resolve({ error: 'Connection timed out', url });
            });
        } catch {
            resolve({ error: 'Invalid URL', url });
        }
    });
}

/**
 * Analyze client-side device data sent from the browser
 */
function analyzeDeviceData(clientData) {
    const findings = [];
    let score = 100;

    // Check WebRTC leak
    if (clientData.webrtcIPs && clientData.webrtcIPs.length > 0) {
        const hasLocalIP = clientData.webrtcIPs.some(
            (ip) => ip.startsWith('192.168.') || ip.startsWith('10.') || ip.startsWith('172.')
        );
        if (hasLocalIP) {
            findings.push({
                category: 'WebRTC',
                severity: 'high',
                title: 'WebRTC Local IP Leak',
                description: 'Your local network IP is exposed through WebRTC',
                leakedIPs: clientData.webrtcIPs.filter(
                    (ip) => ip.startsWith('192.168.') || ip.startsWith('10.') || ip.startsWith('172.')
                ),
            });
            score -= 15;
        }
    }

    // Check Do Not Track
    if (!clientData.doNotTrack || clientData.doNotTrack === 'unspecified') {
        findings.push({
            category: 'Privacy',
            severity: 'medium',
            title: 'Do Not Track Disabled',
            description: 'Your browser is not sending the Do Not Track signal',
        });
        score -= 5;
    }

    // Check cookies
    if (clientData.cookiesEnabled) {
        findings.push({
            category: 'Privacy',
            severity: 'low',
            title: 'Cookies Enabled',
            description: 'Cookies are enabled — websites can track sessions',
        });
        score -= 3;
    }

    // Check third-party cookie blocking
    if (clientData.thirdPartyCookies) {
        findings.push({
            category: 'Privacy',
            severity: 'medium',
            title: 'Third-Party Cookies Allowed',
            description: 'Third-party cookies enable cross-site tracking',
        });
        score -= 8;
    }

    // Check canvas fingerprint
    if (clientData.canvasHash) {
        findings.push({
            category: 'Fingerprint',
            severity: 'medium',
            title: 'Canvas Fingerprint Detectable',
            description: `Your canvas fingerprint hash: ${clientData.canvasHash.substring(0, 16)}...`,
        });
        score -= 5;
    }

    // Check WebGL renderer
    if (clientData.webglRenderer && clientData.webglRenderer !== 'Unknown') {
        findings.push({
            category: 'Fingerprint',
            severity: 'medium',
            title: 'WebGL Renderer Exposed',
            description: `GPU: ${clientData.webglRenderer}`,
        });
        score -= 5;
    }

    // Check plugins
    if (clientData.pluginCount > 0) {
        findings.push({
            category: 'Fingerprint',
            severity: 'low',
            title: 'Browser Plugins Detectable',
            description: `${clientData.pluginCount} plugins detected — increases fingerprint uniqueness`,
        });
        score -= 3;
    }

    // Check screen resolution (fingerprinting)
    if (clientData.screen) {
        findings.push({
            category: 'Fingerprint',
            severity: 'low',
            title: 'Screen Resolution Exposed',
            description: `${clientData.screen} — adds to fingerprint uniqueness`,
        });
        score -= 2;
    }

    // Check timezone
    if (clientData.timezone) {
        findings.push({
            category: 'Fingerprint',
            severity: 'low',
            title: 'Timezone Exposed',
            description: `${clientData.timezone} — reveals approximate geographic location`,
        });
        score -= 2;
    }

    // HTTPS check
    if (clientData.protocol === 'http:') {
        findings.push({
            category: 'Connection',
            severity: 'high',
            title: 'Insecure Connection (HTTP)',
            description: 'Your connection is not encrypted — data can be intercepted',
        });
        score -= 20;
    }

    score = Math.max(0, Math.min(100, score));
    let grade;
    if (score >= 90) grade = 'A+';
    else if (score >= 80) grade = 'A';
    else if (score >= 70) grade = 'B';
    else if (score >= 60) grade = 'C';
    else if (score >= 50) grade = 'D';
    else grade = 'F';

    return {
        score,
        grade,
        findings,
        deviceInfo: {
            userAgent: clientData.userAgent,
            platform: clientData.platform,
            language: clientData.language,
            screen: clientData.screen,
            colorDepth: clientData.colorDepth,
            timezone: clientData.timezone,
            hardwareConcurrency: clientData.hardwareConcurrency,
            deviceMemory: clientData.deviceMemory,
            touchSupport: clientData.touchSupport,
        },
        timestamp: new Date().toISOString(),
    };
}

module.exports = { checkSecurityHeaders, analyzeDeviceData };
