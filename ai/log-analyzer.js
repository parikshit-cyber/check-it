/**
 * CHECK-IT — Log Analysis Engine
 * Parses and analyzes network/system/firewall/auth logs for cybersecurity threats.
 * Supports: Apache, Nginx, Firewall (iptables), Syslog, Auth logs, Windows Event, CSV, and generic logs.
 */

'use strict';

// ═══════════════════════════════════════════════════════════════
// THREAT SIGNATURES & PATTERNS
// ═══════════════════════════════════════════════════════════════

const SQL_INJECTION_PATTERNS = [
    /(\bunion\b.*\bselect\b)/i, /(\bselect\b.*\bfrom\b.*\bwhere\b)/i,
    /(\bor\b\s+\b1\s*=\s*1)/i, /(\bdrop\b\s+\btable\b)/i,
    /(\binsert\b\s+\binto\b)/i, /(\bdelete\b\s+\bfrom\b)/i,
    /('.*--)/i, /(;\s*--)/i, /(\bexec\b\s*\()/i,
    /(\bwaitfor\b\s+\bdelay\b)/i, /(benchmark\s*\()/i,
    /(\bchar\s*\(\d+\))/i, /(\bhaving\b\s+\b1\s*=\s*1)/i,
];

const XSS_PATTERNS = [
    /(<script[\s>])/i, /(javascript\s*:)/i, /(onerror\s*=)/i,
    /(onload\s*=)/i, /(onclick\s*=)/i, /(onmouseover\s*=)/i,
    /(eval\s*\()/i, /(document\.cookie)/i, /(alert\s*\()/i,
    /(img\s+src\s*=.*onerror)/i, /(iframe\s+src)/i,
];

const PATH_TRAVERSAL_PATTERNS = [
    /(\.\.\/)/i, /(\.\.\\)/i, /(%2e%2e%2f)/i, /(%2e%2e\/)/i,
    /(\/etc\/passwd)/i, /(\/etc\/shadow)/i, /(\/proc\/self)/i,
    /(c:\\windows\\system32)/i, /(\/var\/log)/i,
];

const COMMAND_INJECTION_PATTERNS = [
    /(\|\s*\w)/i, /(;\s*\w)/i, /(`.*`)/i, /(\$\(.*\))/i,
    /(\/bin\/sh)/i, /(\/bin\/bash)/i, /(cmd\.exe)/i,
    /(powershell)/i, /(wget\s+http)/i, /(curl\s+http)/i,
];

const SUSPICIOUS_USER_AGENTS = [
    /sqlmap/i, /nikto/i, /nmap/i, /masscan/i, /dirbuster/i,
    /gobuster/i, /wpscan/i, /hydra/i, /metasploit/i, /burpsuite/i,
    /nessus/i, /openvas/i, /zap/i, /acunetix/i, /havij/i,
    /python-requests/i, /go-http-client/i, /libwww-perl/i,
];

const SUSPICIOUS_PATHS = [
    /\/wp-admin/i, /\/wp-login/i, /\/phpmyadmin/i, /\/admin/i,
    /\/\.env/i, /\/\.git/i, /\/\.htaccess/i, /\/config\./i,
    /\/backup/i, /\/shell/i, /\/cmd/i, /\/exec/i,
    /\/wp-content\/uploads/i, /\/cgi-bin/i, /\/xmlrpc\.php/i,
    /\/api\/.*token/i, /\/debug/i, /\/trace/i,
];

const KNOWN_BAD_STATUS_CODES = {
    400: { severity: 'low', label: 'Bad Request' },
    401: { severity: 'medium', label: 'Unauthorized Access Attempt' },
    403: { severity: 'medium', label: 'Forbidden Resource Access' },
    404: { severity: 'low', label: 'Not Found - Potential Enumeration' },
    405: { severity: 'low', label: 'Method Not Allowed' },
    500: { severity: 'high', label: 'Server Error - Potential Exploitation' },
    502: { severity: 'medium', label: 'Bad Gateway' },
    503: { severity: 'medium', label: 'Service Unavailable - Potential DoS' },
};

const MITRE_MAP = {
    'SQL Injection': { id: 'T1190', tactic: 'Initial Access', technique: 'Exploit Public-Facing Application' },
    'XSS Attack': { id: 'T1189', tactic: 'Initial Access', technique: 'Drive-by Compromise' },
    'Path Traversal': { id: 'T1083', tactic: 'Discovery', technique: 'File and Directory Discovery' },
    'Command Injection': { id: 'T1059', tactic: 'Execution', technique: 'Command and Scripting Interpreter' },
    'Brute Force': { id: 'T1110', tactic: 'Credential Access', technique: 'Brute Force' },
    'Port Scan': { id: 'T1046', tactic: 'Discovery', technique: 'Network Service Discovery' },
    'Directory Enumeration': { id: 'T1083', tactic: 'Discovery', technique: 'File and Directory Discovery' },
    'Scanner Activity': { id: 'T1595', tactic: 'Reconnaissance', technique: 'Active Scanning' },
    'Unauthorized Access': { id: 'T1078', tactic: 'Defense Evasion', technique: 'Valid Accounts' },
    'Suspicious User Agent': { id: 'T1592', tactic: 'Reconnaissance', technique: 'Gather Victim Host Information' },
    'Suspicious Status Code': { id: 'T1190', tactic: 'Initial Access', technique: 'Exploit Public-Facing Application' },
    'DDoS Indicator': { id: 'T1498', tactic: 'Impact', technique: 'Network Denial of Service' },
    'Data Exfiltration': { id: 'T1041', tactic: 'Exfiltration', technique: 'Exfiltration Over C2 Channel' },
    'Privilege Escalation': { id: 'T1068', tactic: 'Privilege Escalation', technique: 'Exploitation for Privilege Escalation' },
    'Malware Indicator': { id: 'T1204', tactic: 'Execution', technique: 'User Execution' },
    'Firewall Block': { id: 'T1046', tactic: 'Discovery', technique: 'Network Service Discovery' },
    'Auth Failure': { id: 'T1110', tactic: 'Credential Access', technique: 'Brute Force' },
};

// ═══════════════════════════════════════════════════════════════
// LOG FORMAT PARSERS
// ═══════════════════════════════════════════════════════════════

/**
 * Detect log format from first few lines
 */
function detectLogFormat(lines) {
    const sampleLines = lines.slice(0, 20).filter(l => l.trim());
    if (!sampleLines.length) return 'unknown';

    const sample = sampleLines.join('\n');

    // Apache/Nginx Combined Log Format
    if (/^\d+\.\d+\.\d+\.\d+\s+-\s+-?\s*\[/.test(sampleLines[0])) return 'apache';
    // Syslog
    if (/^[A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+\s+\S+\s+\S+/.test(sampleLines[0])) return 'syslog';
    // Firewall (iptables)
    if (/\biptables\b|\bUFW\b|\bfirewall\b|\bDPT=|\bSPT=/i.test(sample)) return 'firewall';
    // Windows Event Log
    if (/EventID|EventType|Information|Warning|Error|Audit/i.test(sample)) return 'windows';
    // Auth log
    if (/\b(sshd|sudo|login|pam_unix|authentication|Failed password)\b/i.test(sample)) return 'auth';
    // CSV
    if (sampleLines[0].split(',').length >= 3 && sampleLines.length > 1 && sampleLines[1].split(',').length === sampleLines[0].split(',').length) return 'csv';
    // JSON lines
    if (sampleLines[0].trim().startsWith('{')) return 'json';

    return 'generic';
}

/**
 * Parse Apache/Nginx combined log format
 */
function parseApacheLine(line) {
    const regex = /^(\S+)\s+\S+\s+(\S+)\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+(\S+)"\s+(\d+)\s+(\d+)\s+"([^"]*)"\s+"([^"]*)"/;
    const m = line.match(regex);
    if (!m) return null;
    return {
        sourceIP: m[1],
        user: m[2] !== '-' ? m[2] : null,
        timestamp: parseApacheDate(m[3]),
        method: m[4],
        path: m[5],
        protocol: m[6],
        statusCode: parseInt(m[7]),
        bytes: parseInt(m[8]),
        referer: m[9] !== '-' ? m[9] : null,
        userAgent: m[10],
        raw: line,
    };
}

function parseApacheDate(str) {
    // 10/Oct/2023:13:55:36 -0700
    const months = { Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5, Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11 };
    const m = str.match(/(\d+)\/(\w+)\/(\d+):(\d+):(\d+):(\d+)/);
    if (!m) return new Date().toISOString();
    return new Date(parseInt(m[3]), months[m[2]] || 0, parseInt(m[1]), parseInt(m[4]), parseInt(m[5]), parseInt(m[6])).toISOString();
}

/**
 * Parse syslog format
 */
function parseSyslogLine(line) {
    const regex = /^(\w+\s+\d+\s+[\d:]+)\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s*(.*)/;
    const m = line.match(regex);
    if (!m) return null;
    const year = new Date().getFullYear();
    return {
        timestamp: new Date(`${m[1]} ${year}`).toISOString(),
        hostname: m[2],
        process: m[3],
        pid: m[4] || null,
        message: m[5],
        raw: line,
    };
}

/**
 * Parse firewall log format (iptables-like)
 */
function parseFirewallLine(line) {
    const entry = { raw: line };
    // Timestamp from syslog prefix
    const tsMatch = line.match(/^(\w+\s+\d+\s+[\d:]+)/);
    if (tsMatch) entry.timestamp = new Date(`${tsMatch[1]} ${new Date().getFullYear()}`).toISOString();
    else entry.timestamp = new Date().toISOString();

    const srcMatch = line.match(/SRC=(\S+)/);
    const dstMatch = line.match(/DST=(\S+)/);
    const sptMatch = line.match(/SPT=(\d+)/);
    const dptMatch = line.match(/DPT=(\d+)/);
    const protoMatch = line.match(/PROTO=(\S+)/);
    const actionMatch = line.match(/(ACCEPT|DROP|REJECT|DENY|BLOCK|ALLOW)/i);

    entry.sourceIP = srcMatch ? srcMatch[1] : null;
    entry.destIP = dstMatch ? dstMatch[1] : null;
    entry.sourcePort = sptMatch ? parseInt(sptMatch[1]) : null;
    entry.destPort = dptMatch ? parseInt(dptMatch[1]) : null;
    entry.protocol = protoMatch ? protoMatch[1] : null;
    entry.action = actionMatch ? actionMatch[1].toUpperCase() : 'UNKNOWN';

    return entry;
}

/**
 * Parse auth log format
 */
function parseAuthLine(line) {
    const entry = parseSyslogLine(line);
    if (!entry) return null;

    // Enhance with auth-specific parsing
    const ipMatch = line.match(/from\s+(\d+\.\d+\.\d+\.\d+)/);
    const userMatch = line.match(/(?:user|for)\s+(\S+)/);
    const failedMatch = /(?:Failed|failure|invalid|denied|refused|error)/i.test(line);
    const successMatch = /(?:Accepted|success|opened|session opened)/i.test(line);

    entry.sourceIP = ipMatch ? ipMatch[1] : null;
    entry.user = userMatch ? userMatch[1] : null;
    entry.authResult = failedMatch ? 'FAILED' : successMatch ? 'SUCCESS' : 'INFO';
    return entry;
}

/**
 * Parse generic/unknown format — best-effort extraction
 */
function parseGenericLine(line, index) {
    const entry = { raw: line, index };

    // Try to extract timestamp
    const tsPatterns = [
        /(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})/,
        /(\d{2}\/\d{2}\/\d{4}\s+\d{2}:\d{2}:\d{2})/,
        /(\w+\s+\d+\s+\d{2}:\d{2}:\d{2})/,
        /(\d+\/\w+\/\d{4}:\d{2}:\d{2}:\d{2})/,
    ];
    for (const p of tsPatterns) {
        const m = line.match(p);
        if (m) { entry.timestamp = new Date(m[1]).toISOString(); break; }
    }
    if (!entry.timestamp) entry.timestamp = new Date().toISOString();

    // Try to extract IP
    const ipMatch = line.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
    entry.sourceIP = ipMatch ? ipMatch[1] : null;

    // Try to extract severity
    if (/\b(CRITICAL|CRIT|EMERGENCY|EMERG)\b/i.test(line)) entry.logLevel = 'CRITICAL';
    else if (/\b(ERROR|ERR|FATAL)\b/i.test(line)) entry.logLevel = 'ERROR';
    else if (/\b(WARN|WARNING)\b/i.test(line)) entry.logLevel = 'WARNING';
    else if (/\b(INFO|NOTICE)\b/i.test(line)) entry.logLevel = 'INFO';
    else if (/\b(DEBUG|TRACE)\b/i.test(line)) entry.logLevel = 'DEBUG';
    else entry.logLevel = 'INFO';

    entry.message = line;
    return entry;
}

/**
 * Parse CSV log format
 */
function parseCSVLine(line, headers) {
    const values = line.split(',').map(v => v.trim().replace(/^["']|["']$/g, ''));
    const entry = { raw: line };
    headers.forEach((h, i) => { entry[h.toLowerCase().replace(/\s+/g, '_')] = values[i] || ''; });

    // Try to identify fields
    const allKeys = Object.keys(entry).join(' ').toLowerCase();
    if (!entry.sourceIP) {
        for (const k of Object.keys(entry)) {
            if (/ip|source|src|addr/i.test(k) && /\d+\.\d+\.\d+\.\d+/.test(entry[k])) {
                entry.sourceIP = entry[k]; break;
            }
        }
    }
    if (!entry.timestamp) {
        for (const k of Object.keys(entry)) {
            if (/time|date|ts|stamp/i.test(k)) {
                const d = new Date(entry[k]);
                if (!isNaN(d)) { entry.timestamp = d.toISOString(); break; }
            }
        }
    }
    if (!entry.timestamp) entry.timestamp = new Date().toISOString();
    return entry;
}

/**
 * Parse JSON log line
 */
function parseJSONLine(line) {
    try {
        const obj = JSON.parse(line);
        const entry = { ...obj, raw: line };
        // Normalize common fields
        if (!entry.timestamp && (obj.time || obj.ts || obj.date || obj['@timestamp'])) {
            entry.timestamp = new Date(obj.time || obj.ts || obj.date || obj['@timestamp']).toISOString();
        }
        if (!entry.timestamp) entry.timestamp = new Date().toISOString();
        if (!entry.sourceIP && (obj.ip || obj.src || obj.source_ip || obj.client_ip || obj.remote_addr)) {
            entry.sourceIP = obj.ip || obj.src || obj.source_ip || obj.client_ip || obj.remote_addr;
        }
        if (!entry.message && (obj.msg || obj.message || obj.log)) {
            entry.message = obj.msg || obj.message || obj.log;
        }
        return entry;
    } catch { return null; }
}


// ═══════════════════════════════════════════════════════════════
// THREAT ANALYSIS ENGINE
// ═══════════════════════════════════════════════════════════════

function analyzeEntryThreats(entry, allEntries, entryIndex) {
    const threats = [];
    const content = (entry.path || '') + ' ' + (entry.message || '') + ' ' + (entry.userAgent || '') + ' ' + (entry.raw || '');
    const contentLower = content.toLowerCase();

    // SQL Injection
    for (const p of SQL_INJECTION_PATTERNS) {
        if (p.test(content)) {
            threats.push({
                type: 'SQL Injection',
                severity: 'critical',
                detail: `SQL injection pattern detected: ${p.toString().slice(1, 40)}...`,
                confidence: 'high',
            });
            break;
        }
    }

    // XSS
    for (const p of XSS_PATTERNS) {
        if (p.test(content)) {
            threats.push({
                type: 'XSS Attack',
                severity: 'high',
                detail: `Cross-site scripting pattern found in request`,
                confidence: 'high',
            });
            break;
        }
    }

    // Path Traversal
    for (const p of PATH_TRAVERSAL_PATTERNS) {
        if (p.test(content)) {
            threats.push({
                type: 'Path Traversal',
                severity: 'high',
                detail: `Directory traversal attempt detected`,
                confidence: 'high',
            });
            break;
        }
    }

    // Command Injection
    for (const p of COMMAND_INJECTION_PATTERNS) {
        if (p.test(entry.path || '') || p.test(entry.message || '')) {
            threats.push({
                type: 'Command Injection',
                severity: 'critical',
                detail: `Potential command injection in request`,
                confidence: 'medium',
            });
            break;
        }
    }

    // Suspicious User Agent
    if (entry.userAgent) {
        for (const p of SUSPICIOUS_USER_AGENTS) {
            if (p.test(entry.userAgent)) {
                threats.push({
                    type: 'Scanner Activity',
                    severity: 'medium',
                    detail: `Known security scanner user agent: ${entry.userAgent.slice(0, 60)}`,
                    confidence: 'high',
                });
                break;
            }
        }
    }

    // Suspicious Paths
    if (entry.path) {
        for (const p of SUSPICIOUS_PATHS) {
            if (p.test(entry.path)) {
                threats.push({
                    type: 'Directory Enumeration',
                    severity: 'medium',
                    detail: `Access to sensitive path: ${entry.path}`,
                    confidence: 'medium',
                });
                break;
            }
        }
    }

    // Suspicious Status Codes
    if (entry.statusCode && KNOWN_BAD_STATUS_CODES[entry.statusCode]) {
        const sc = KNOWN_BAD_STATUS_CODES[entry.statusCode];
        threats.push({
            type: 'Suspicious Status Code',
            severity: sc.severity,
            detail: `HTTP ${entry.statusCode}: ${sc.label}`,
            confidence: 'medium',
        });
    }

    // Firewall blocks
    if (entry.action && /DROP|REJECT|DENY|BLOCK/i.test(entry.action)) {
        threats.push({
            type: 'Firewall Block',
            severity: 'medium',
            detail: `Firewall ${entry.action}: ${entry.sourceIP || '?'} → ${entry.destIP || '?'}:${entry.destPort || '?'}`,
            confidence: 'high',
        });
    }

    // Auth failures
    if (entry.authResult === 'FAILED') {
        threats.push({
            type: 'Auth Failure',
            severity: 'medium',
            detail: `Authentication failure${entry.user ? ` for user: ${entry.user}` : ''}${entry.sourceIP ? ` from ${entry.sourceIP}` : ''}`,
            confidence: 'high',
        });
    }

    // Brute force detection (check frequency from same IP)
    if (entry.sourceIP && allEntries) {
        const sameIPEntries = allEntries.filter(e => e.sourceIP === entry.sourceIP);
        if (sameIPEntries.length > 20) {
            const hasFailures = sameIPEntries.filter(e => e.authResult === 'FAILED' || e.statusCode === 401 || e.statusCode === 403).length;
            if (hasFailures > 5) {
                threats.push({
                    type: 'Brute Force',
                    severity: 'high',
                    detail: `${hasFailures} failed attempts from ${entry.sourceIP} (${sameIPEntries.length} total requests)`,
                    confidence: 'high',
                });
            }
        }
        // Port scan detection
        if (entry.destPort) {
            const uniquePorts = new Set(sameIPEntries.filter(e => e.destPort).map(e => e.destPort));
            if (uniquePorts.size > 10) {
                threats.push({
                    type: 'Port Scan',
                    severity: 'high',
                    detail: `${uniquePorts.size} unique ports probed from ${entry.sourceIP}`,
                    confidence: 'high',
                });
            }
        }
    }

    // DDoS indicator (many requests in short time)
    if (entry.sourceIP && allEntries) {
        const sameIPCount = allEntries.filter(e => e.sourceIP === entry.sourceIP).length;
        if (sameIPCount > 100) {
            threats.push({
                type: 'DDoS Indicator',
                severity: 'high',
                detail: `Excessive requests: ${sameIPCount} from ${entry.sourceIP}`,
                confidence: 'medium',
            });
        }
    }

    // Privilege escalation keywords
    if (/sudo|su\s+root|privilege|escalat|root\s+access|admin\s+grant/i.test(contentLower)) {
        threats.push({
            type: 'Privilege Escalation',
            severity: 'high',
            detail: `Privilege escalation indicators detected`,
            confidence: 'medium',
        });
    }

    // Data exfiltration
    if (entry.bytes && entry.bytes > 10000000) {
        threats.push({
            type: 'Data Exfiltration',
            severity: 'high',
            detail: `Large data transfer: ${(entry.bytes / 1048576).toFixed(1)} MB`,
            confidence: 'low',
        });
    }

    // Malware indicators
    if (/malware|trojan|ransomware|cryptominer|botnet|c2\s*server|callback|beacon/i.test(contentLower)) {
        threats.push({
            type: 'Malware Indicator',
            severity: 'critical',
            detail: `Malware-related keywords detected in log entry`,
            confidence: 'medium',
        });
    }

    // Deduplicate threats by type
    const seen = new Set();
    const unique = [];
    for (const t of threats) {
        if (!seen.has(t.type)) { seen.add(t.type); unique.push(t); }
    }

    return unique;
}

function calculateSeverity(threats) {
    if (!threats.length) return 'info';
    const severities = threats.map(t => t.severity);
    if (severities.includes('critical')) return 'critical';
    if (severities.includes('high')) return 'high';
    if (severities.includes('medium')) return 'medium';
    if (severities.includes('low')) return 'low';
    return 'info';
}

function severityScore(sev) {
    return { critical: 100, high: 75, medium: 50, low: 25, info: 5 }[sev] || 0;
}

function severityColor(sev) {
    return {
        critical: '#ff006e',
        high: '#ff3366',
        medium: '#ffb800',
        low: '#00f0ff',
        info: '#00ff88',
    }[sev] || '#00f0ff';
}


// ═══════════════════════════════════════════════════════════════
// MAIN ANALYSIS FUNCTIONS
// ═══════════════════════════════════════════════════════════════

/**
 * Analyze a full log file buffer
 * @param {Buffer} fileBuffer — the raw uploaded file
 * @param {string} formatHint — optional format hint (auto, apache, firewall, syslog, auth, windows, csv, json)
 * @returns {Object} — full analysis result
 */
function analyzeLogFile(fileBuffer, formatHint) {
    const text = fileBuffer.toString('utf-8');
    const rawLines = text.split(/\r?\n/).filter(l => l.trim());

    if (!rawLines.length) {
        return { error: 'Log file is empty or contains no valid lines.' };
    }

    // Detect format
    const format = (formatHint && formatHint !== 'auto') ? formatHint : detectLogFormat(rawLines);

    // Parse lines
    let csvHeaders = null;
    const entries = [];
    for (let i = 0; i < rawLines.length; i++) {
        let entry = null;
        switch (format) {
            case 'apache':
                entry = parseApacheLine(rawLines[i]);
                break;
            case 'syslog':
                entry = parseSyslogLine(rawLines[i]);
                break;
            case 'firewall':
                entry = parseFirewallLine(rawLines[i]);
                break;
            case 'auth':
                entry = parseAuthLine(rawLines[i]);
                break;
            case 'csv':
                if (i === 0) { csvHeaders = rawLines[0].split(',').map(h => h.trim().replace(/^["']|["']$/g, '')); continue; }
                entry = parseCSVLine(rawLines[i], csvHeaders || []);
                break;
            case 'json':
                entry = parseJSONLine(rawLines[i]);
                break;
            default:
                entry = parseGenericLine(rawLines[i], i);
        }
        if (entry) {
            entry.lineNumber = i + 1;
            entry.id = `log-${i}-${Date.now().toString(36)}`;
            entries.push(entry);
        }
    }

    if (!entries.length) {
        return { error: 'Could not parse any log entries. Try a different format.' };
    }

    // Analyze each entry for threats
    const analyzedEntries = entries.map((entry, idx) => {
        const threats = analyzeEntryThreats(entry, entries, idx);
        const severity = calculateSeverity(threats);
        return {
            ...entry,
            threats,
            severity,
            severityScore: severityScore(severity),
            severityColor: severityColor(severity),
            threatCount: threats.length,
        };
    });

    // Build summary
    const totalEntries = analyzedEntries.length;
    const threatsFound = analyzedEntries.filter(e => e.threats.length > 0).length;
    const severityDistribution = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    const threatCategories = {};
    const sourceIPs = {};
    const timelineData = {};
    const statusCodeDist = {};

    for (const entry of analyzedEntries) {
        severityDistribution[entry.severity] = (severityDistribution[entry.severity] || 0) + 1;

        for (const t of entry.threats) {
            threatCategories[t.type] = (threatCategories[t.type] || 0) + 1;
        }

        if (entry.sourceIP) {
            sourceIPs[entry.sourceIP] = (sourceIPs[entry.sourceIP] || 0) + 1;
        }

        if (entry.statusCode) {
            statusCodeDist[entry.statusCode] = (statusCodeDist[entry.statusCode] || 0) + 1;
        }

        // Timeline (group by hour)
        try {
            const d = new Date(entry.timestamp);
            if (!isNaN(d)) {
                const hourKey = `${String(d.getHours()).padStart(2, '0')}:00`;
                if (!timelineData[hourKey]) timelineData[hourKey] = { total: 0, threats: 0 };
                timelineData[hourKey].total++;
                if (entry.threats.length) timelineData[hourKey].threats++;
            }
        } catch { }
    }

    // Overall risk score
    const avgScore = analyzedEntries.reduce((sum, e) => sum + e.severityScore, 0) / totalEntries;
    const criticalWeight = severityDistribution.critical * 10 + severityDistribution.high * 5 + severityDistribution.medium * 2;
    const overallRisk = Math.min(100, Math.round(avgScore * 0.3 + (threatsFound / totalEntries) * 100 * 0.4 + Math.min(criticalWeight, 100) * 0.3));

    const riskLevel = overallRisk >= 80 ? 'critical' : overallRisk >= 60 ? 'high' : overallRisk >= 35 ? 'medium' : overallRisk >= 15 ? 'low' : 'clean';

    // Top source IPs
    const topIPs = Object.entries(sourceIPs).sort((a, b) => b[1] - a[1]).slice(0, 10).map(([ip, count]) => ({ ip, count }));

    // Top threat categories
    const topThreats = Object.entries(threatCategories).sort((a, b) => b[1] - a[1]).map(([type, count]) => ({
        type,
        count,
        mitre: MITRE_MAP[type] || null,
    }));

    // Timeline sorted
    const timeline = Object.entries(timelineData).sort((a, b) => a[0].localeCompare(b[0])).map(([hour, data]) => ({
        hour,
        total: data.total,
        threats: data.threats,
    }));

    // Entries for table (limit to 500 for performance, send summary for rest)
    const tableEntries = analyzedEntries.slice(0, 500).map(e => ({
        id: e.id,
        lineNumber: e.lineNumber,
        timestamp: e.timestamp,
        sourceIP: e.sourceIP || '—',
        method: e.method || e.action || e.process || '—',
        path: e.path || e.message?.slice(0, 80) || '—',
        statusCode: e.statusCode || '—',
        severity: e.severity,
        severityColor: e.severityColor,
        threatCount: e.threatCount,
        threats: e.threats.map(t => t.type),
    }));

    return {
        success: true,
        format,
        analyzedAt: new Date().toISOString(),
        summary: {
            totalEntries,
            threatsFound,
            cleanEntries: totalEntries - threatsFound,
            overallRisk,
            riskLevel,
            riskColor: severityColor(riskLevel === 'clean' ? 'info' : riskLevel),
            severityDistribution,
            topThreats,
            topIPs,
            timeline,
            statusCodeDistribution: statusCodeDist,
        },
        entries: tableEntries,
    };
}

/**
 * Deep-dive analysis for a single log entry
 * @param {string} rawEntry — the raw log line text
 * @param {string} format — log format hint
 * @returns {Object} — detailed analysis
 */
function analyzeLogEntry(rawEntry, format) {
    if (!rawEntry || typeof rawEntry !== 'string') {
        return { error: 'No log entry provided.' };
    }

    // Parse the entry
    let entry;
    switch (format) {
        case 'apache': entry = parseApacheLine(rawEntry); break;
        case 'syslog': entry = parseSyslogLine(rawEntry); break;
        case 'firewall': entry = parseFirewallLine(rawEntry); break;
        case 'auth': entry = parseAuthLine(rawEntry); break;
        case 'json': entry = parseJSONLine(rawEntry); break;
        default: entry = parseGenericLine(rawEntry, 0);
    }
    if (!entry) entry = parseGenericLine(rawEntry, 0);

    // Analyze threats
    const threats = analyzeEntryThreats(entry, null, 0);
    const severity = calculateSeverity(threats);
    const score = severityScore(severity);

    // Build vulnerability report
    const vulnerabilities = threats.map(t => {
        const mitre = MITRE_MAP[t.type] || {};
        return {
            type: t.type,
            severity: t.severity,
            detail: t.detail,
            confidence: t.confidence,
            mitre: mitre.id ? {
                id: mitre.id,
                tactic: mitre.tactic,
                technique: mitre.technique,
                url: `https://attack.mitre.org/techniques/${mitre.id}/`,
            } : null,
            remediation: getRemediation(t.type),
            iocs: extractIOCs(entry, t),
        };
    });

    // Extract all IOCs from entry
    const allIOCs = {
        ips: [],
        urls: [],
        paths: [],
        userAgents: [],
        ports: [],
    };
    const ipMatches = rawEntry.match(/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/g);
    if (ipMatches) allIOCs.ips = [...new Set(ipMatches)];
    const urlMatches = rawEntry.match(/https?:\/\/[^\s"']+/gi);
    if (urlMatches) allIOCs.urls = [...new Set(urlMatches)];
    if (entry.path) allIOCs.paths.push(entry.path);
    if (entry.userAgent) allIOCs.userAgents.push(entry.userAgent);
    if (entry.destPort) allIOCs.ports.push(entry.destPort);
    if (entry.sourcePort) allIOCs.ports.push(entry.sourcePort);

    // Parsed fields
    const parsedFields = {};
    for (const [k, v] of Object.entries(entry)) {
        if (k !== 'raw' && v !== null && v !== undefined) parsedFields[k] = v;
    }

    return {
        success: true,
        raw: rawEntry,
        format,
        parsedFields,
        riskScore: score,
        severity,
        severityColor: severityColor(severity),
        riskLevel: severity === 'info' ? 'clean' : severity,
        vulnerabilities,
        totalVulnerabilities: vulnerabilities.length,
        iocs: allIOCs,
        recommendations: generateEntryRecommendations(threats, entry),
        analyzedAt: new Date().toISOString(),
    };
}

function getRemediation(threatType) {
    const remediations = {
        'SQL Injection': [
            'Implement parameterized queries / prepared statements',
            'Use an ORM to abstract database operations',
            'Validate and sanitize all user input',
            'Deploy a Web Application Firewall (WAF)',
            'Apply principle of least privilege for database accounts',
        ],
        'XSS Attack': [
            'Implement Content Security Policy (CSP) headers',
            'Sanitize and encode all output',
            'Use frameworks with built-in XSS protection',
            'Validate input on both client and server side',
            'Set HttpOnly and Secure flags on cookies',
        ],
        'Path Traversal': [
            'Validate and sanitize file path inputs',
            'Use chroot jails or containerization',
            'Implement proper access control on file system',
            'Disable directory listing on web server',
            'Use allowlists for accessible directories',
        ],
        'Command Injection': [
            'Avoid system calls with user-supplied input',
            'Use parameterized APIs instead of shell commands',
            'Implement strict input validation with allowlists',
            'Run application with minimal privileges',
            'Use sandboxing for command execution',
        ],
        'Brute Force': [
            'Implement account lockout after N failed attempts',
            'Deploy rate limiting and CAPTCHA',
            'Use multi-factor authentication (MFA)',
            'Monitor login patterns and alert on anomalies',
            'Implement IP-based blocking for repeat offenders',
        ],
        'Port Scan': [
            'Configure firewall to block scanning IPs',
            'Disable unnecessary open ports',
            'Implement IDS/IPS rules for scan detection',
            'Use port knocking for sensitive services',
            'Monitor network traffic for scan patterns',
        ],
        'Directory Enumeration': [
            'Return consistent responses for all paths (avoid info leakage)',
            'Implement rate limiting on 404 responses',
            'Use custom error pages without internal information',
            'Block common scanner user agents',
            'Monitor for rapid sequential requests to different paths',
        ],
        'Scanner Activity': [
            'Block known scanner user agents at WAF/reverse proxy',
            'Implement rate limiting',
            'Deploy honeypots to detect and trap scanners',
            'Monitor for automated scanning patterns',
            'Use CAPTCHA on sensitive endpoints',
        ],
        'Firewall Block': [
            'Review firewall rules for completeness',
            'Investigate blocked source IP for broader attack campaign',
            'Update threat intelligence feeds',
            'Ensure logging captures all necessary metadata',
            'Consider geo-blocking if attacks originate from specific regions',
        ],
        'Auth Failure': [
            'Implement progressive delays for failed login attempts',
            'Enable multi-factor authentication',
            'Monitor for credential stuffing patterns',
            'Review password policies and enforce complexity',
            'Alert on multiple failed attempts from same source',
        ],
        'DDoS Indicator': [
            'Enable DDoS protection (CDN, cloud-based)',
            'Implement rate limiting at application and network level',
            'Configure auto-scaling to absorb traffic spikes',
            'Block offending IPs at network edge',
            'Set up traffic analysis and anomaly detection',
        ],
        'Data Exfiltration': [
            'Implement Data Loss Prevention (DLP) tools',
            'Monitor outbound data volume anomalies',
            'Encrypt sensitive data at rest and in transit',
            'Restrict large data transfers without approval',
            'Enable SIEM alerts for unusual data movement',
        ],
        'Privilege Escalation': [
            'Apply principle of least privilege',
            'Audit sudo/admin access regularly',
            'Monitor privilege changes in real-time',
            'Use mandatory access control (SELinux, AppArmor)',
            'Detect and alert on unusual privilege operations',
        ],
        'Malware Indicator': [
            'Isolate affected system immediately',
            'Run comprehensive antivirus/malware scan',
            'Check for persistence mechanisms (cron, startup)',
            'Review network connections for C2 callbacks',
            'Preserve forensic evidence before remediation',
        ],
    };
    return remediations[threatType] || ['Monitor this activity closely', 'Review security policies', 'Consider implementing additional logging'];
}

function extractIOCs(entry, threat) {
    const iocs = [];
    if (entry.sourceIP) iocs.push({ type: 'IP Address', value: entry.sourceIP });
    if (entry.path) iocs.push({ type: 'URL Path', value: entry.path });
    if (entry.userAgent && threat.type === 'Scanner Activity') iocs.push({ type: 'User Agent', value: entry.userAgent });
    if (entry.destPort) iocs.push({ type: 'Port', value: String(entry.destPort) });
    return iocs;
}

function generateEntryRecommendations(threats, entry) {
    const recs = [];
    if (!threats.length) {
        recs.push('No immediate threats detected. Continue monitoring.');
        return recs;
    }

    const types = new Set(threats.map(t => t.type));

    if (types.has('SQL Injection') || types.has('XSS Attack') || types.has('Command Injection')) {
        recs.push('🚨 URGENT: Block the source IP immediately and investigate for successful exploitation');
        recs.push('Review application logs for any data access or modification from this source');
    }
    if (types.has('Brute Force') || types.has('Auth Failure')) {
        recs.push('Temporarily block the source IP and review all accounts for compromise');
        recs.push('Enable MFA on all accounts immediately if not already active');
    }
    if (types.has('Port Scan') || types.has('Scanner Activity')) {
        recs.push('Add source IP to blocklist and review exposed services');
        recs.push('Check if any vulnerabilities were discovered and exploited');
    }
    if (types.has('Privilege Escalation')) {
        recs.push('Audit all recent privilege changes and verify legitimacy');
        recs.push('Review system integrity and check for unauthorized modifications');
    }
    if (types.has('Malware Indicator')) {
        recs.push('Isolate the affected system from the network immediately');
        recs.push('Initiate incident response procedures');
    }
    if (entry.sourceIP) {
        recs.push(`Investigate source IP ${entry.sourceIP} in threat intelligence platforms`);
    }

    return [...new Set(recs)].slice(0, 6);
}

// ═══════════════════════════════════════════════════════════════
// EXPORTS
// ═══════════════════════════════════════════════════════════════

module.exports = {
    analyzeLogFile,
    analyzeLogEntry,
};
