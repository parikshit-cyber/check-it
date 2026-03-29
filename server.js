require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const multer = require('multer');
const http = require('http');
const https = require('https');
const { analyzeUrl } = require('./ai/phishing-model');
const { lookupIP } = require('./ai/ip-intelligence');
const { analyzeEmail } = require('./ai/email-analyzer');
const { analyzeUsername, analyzeWebsite, analyzeEmailOSINT, analyzePhone, analyzeDomainOSINT } = require('./ai/osint-engine');
const { analyzeLogFile, analyzeLogEntry } = require('./ai/log-analyzer');
const { fetchCyberNews } = require('./ai/cyber-news-engine');
const { fetchLiveThreats } = require('./ai/threat-feed-engine');
// New engines
const linkTracker = require('./ai/link-tracker-engine');
const { checkSecurityHeaders, analyzeDeviceData } = require('./ai/device-security-engine');
const { dnsLeakTest, portScan, sslCheck, latencyTest } = require('./ai/network-engine');
const { checkEmail: checkDarkWeb } = require('./ai/darkweb-engine');
const { generateBatch: generateAttackBatch } = require('./ai/attack-map-engine');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Multer for .eml file uploads (memory storage)
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 10 * 1024 * 1024 } });
// Multer for log file uploads
const logUpload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 50 * 1024 * 1024 } });

// ─────────────────────────────────────────────
// API: User Info (Public IP + ISP)
// Uses ip-api.com (free, 45 req/min) as primary, with fallback chain
// ─────────────────────────────────────────────
app.get('/api/user-info', async (req, res) => {
  /**
   * Helper to fetch JSON from a URL (supports both http and https).
   */
  function fetchJSON(url) {
    const lib = url.startsWith('https') ? https : http;
    return new Promise((resolve, reject) => {
      lib.get(url, (response) => {
        // Handle redirects
        if (response.statusCode >= 300 && response.statusCode < 400 && response.headers.location) {
          return fetchJSON(response.headers.location).then(resolve).catch(reject);
        }
        if (response.statusCode !== 200) {
          return reject(new Error(`HTTP ${response.statusCode}`));
        }
        let body = '';
        response.on('data', chunk => body += chunk);
        response.on('end', () => {
          try { resolve(JSON.parse(body)); } catch (e) { reject(e); }
        });
        response.on('error', reject);
      }).on('error', reject);
    });
  }

  try {
    // Primary: ip-api.com (same API used by ip-intelligence.js, reliable and fast)
    const data = await fetchJSON(
      'http://ip-api.com/json/?fields=query,isp,org,city,regionName,country,lat,lon,timezone,as'
    );

    if (data && data.query) {
      return res.json({
        ip: data.query,
        isp: data.isp || data.org || 'Unknown ISP',
        city: data.city || '',
        region: data.regionName || '',
        country: data.country || '',
        lat: data.lat || 0,
        lng: data.lon || 0,
        timezone: data.timezone || '',
      });
    }
  } catch (err) {
    console.warn('ip-api.com failed, trying fallback:', err.message);
  }

  // Fallback: ipapi.co
  try {
    const data = await fetchJSON('https://ipapi.co/json/');

    if (data && data.ip) {
      return res.json({
        ip: data.ip,
        isp: data.org || 'Unknown ISP',
        city: data.city || '',
        region: data.region || '',
        country: data.country_name || '',
        lat: data.latitude || 0,
        lng: data.longitude || 0,
        timezone: data.timezone || '',
      });
    }
  } catch (err) {
    console.warn('ipapi.co also failed:', err.message);
  }

  // Last resort fallback
  res.json({
    ip: req.headers['x-forwarded-for']?.split(',')[0]?.trim() || 'Unavailable',
    isp: 'Unavailable',
    city: '', region: '', country: '', lat: 0, lng: 0, timezone: '',
  });
});

// ─────────────────────────────────────────────
// API: Global Live News Feed (Real RSS from cybersecurity sources)
// ─────────────────────────────────────────────
app.get('/api/news/live', async (req, res) => {
  try {
    const allNews = await fetchCyberNews();
    // Return 8-12 random items from the cached pool
    const count = Math.min(allNews.length, Math.floor(Math.random() * 5) + 8);
    const shuffled = [...allNews].sort(() => Math.random() - 0.5);
    const selected = shuffled.slice(0, count);
    res.json({ news: selected, totalCount: allNews.length });
  } catch (err) {
    console.error('News feed error:', err);
    res.json({ news: [], totalCount: 0 });
  }
});

// ─────────────────────────────────────────────
// API: Phishing URL Analysis
// ─────────────────────────────────────────────
app.post('/api/phishing/analyze', (req, res) => {
  try {
    const { url } = req.body;
    if (!url || typeof url !== 'string') {
      return res.status(400).json({ error: 'A valid URL string is required.' });
    }
    const result = analyzeUrl(url);
    res.json(result);
  } catch (err) {
    console.error('Phishing analysis error:', err);
    res.status(500).json({ error: 'Analysis failed.' });
  }
});

// ─────────────────────────────────────────────
// API: IP Intelligence Lookup
// ─────────────────────────────────────────────
app.post('/api/ip/lookup', async (req, res) => {
  try {
    const { ip } = req.body;
    if (!ip || typeof ip !== 'string') {
      return res.status(400).json({ error: 'A valid IP address string is required.' });
    }
    const result = await lookupIP(ip);
    res.json(result);
  } catch (err) {
    console.error('IP lookup error:', err);
    res.status(500).json({ error: 'IP lookup failed.' });
  }
});

// ─────────────────────────────────────────────
// API: Email Phishing Analysis (.eml upload)
// ─────────────────────────────────────────────
app.post('/api/email/analyze', upload.single('emlFile'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No .eml file uploaded.' });
    }
    const result = await analyzeEmail(req.file.buffer);
    res.json(result);
  } catch (err) {
    console.error('Email analysis error:', err);
    res.status(500).json({ error: 'Email analysis failed: ' + err.message });
  }
});

// ─────────────────────────────────────────────
// API: Live Threat Feed (Real data from abuse.ch)
// ─────────────────────────────────────────────
app.get('/api/threats/live', async (req, res) => {
  try {
    const { threats, stats } = await fetchLiveThreats();
    res.json({
      totalBlocked: stats.totalBlocked,
      activeThreats: stats.activeThreats,
      threatsPerMinute: stats.threatsPerMinute,
      threats,
    });
  } catch (err) {
    console.error('Threat feed error:', err);
    res.json({ totalBlocked: 0, activeThreats: 0, threatsPerMinute: 0, threats: [] });
  }
});

// ─────────────────────────────────────────────
// API: OSINT Analysis
// ─────────────────────────────────────────────
app.post('/api/osint/username', async (req, res) => {
  try {
    const { username } = req.body;
    if (!username || typeof username !== 'string') return res.status(400).json({ error: 'A username string is required.' });
    const result = await analyzeUsername(username);
    res.json(result);
  } catch (err) {
    console.error('OSINT username error:', err);
    res.status(500).json({ error: 'Username analysis failed.' });
  }
});

app.post('/api/osint/website', async (req, res) => {
  try {
    const { url } = req.body;
    if (!url || typeof url !== 'string') return res.status(400).json({ error: 'A URL string is required.' });
    const result = await analyzeWebsite(url);
    res.json(result);
  } catch (err) {
    console.error('OSINT website error:', err);
    res.status(500).json({ error: 'Website analysis failed: ' + err.message });
  }
});

app.post('/api/osint/email', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email || typeof email !== 'string') return res.status(400).json({ error: 'An email string is required.' });
    const result = await analyzeEmailOSINT(email);
    res.json(result);
  } catch (err) {
    console.error('OSINT email error:', err);
    res.status(500).json({ error: 'Email analysis failed.' });
  }
});

app.post('/api/osint/phone', async (req, res) => {
  try {
    const { phone } = req.body;
    if (!phone || typeof phone !== 'string') return res.status(400).json({ error: 'A phone number string is required.' });
    const result = await analyzePhone(phone);
    res.json(result);
  } catch (err) {
    console.error('OSINT phone error:', err);
    res.status(500).json({ error: 'Phone analysis failed.' });
  }
});

app.post('/api/osint/domain', async (req, res) => {
  try {
    const { domain } = req.body;
    if (!domain || typeof domain !== 'string') return res.status(400).json({ error: 'A domain string is required.' });
    const result = await analyzeDomainOSINT(domain);
    res.json(result);
  } catch (err) {
    console.error('OSINT domain error:', err);
    res.status(500).json({ error: 'Domain analysis failed.' });
  }
});

// ─────────────────────────────────────────────
// API: Log Analysis (file upload)
// ─────────────────────────────────────────────
app.post('/api/logs/analyze', logUpload.single('logFile'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No log file uploaded.' });
    }
    const format = req.body.format || 'auto';
    const result = analyzeLogFile(req.file.buffer, format);
    res.json(result);
  } catch (err) {
    console.error('Log analysis error:', err);
    res.status(500).json({ error: 'Log analysis failed: ' + err.message });
  }
});

app.post('/api/logs/entry/analyze', (req, res) => {
  try {
    const { raw, format } = req.body;
    if (!raw || typeof raw !== 'string') {
      return res.status(400).json({ error: 'A raw log entry string is required.' });
    }
    const result = analyzeLogEntry(raw, format || 'generic');
    res.json(result);
  } catch (err) {
    console.error('Log entry analysis error:', err);
    res.status(500).json({ error: 'Entry analysis failed: ' + err.message });
  }
});

// ─────────────────────────────────────────────
// SSE: Live Network Traffic Stream
// ─────────────────────────────────────────────
app.get('/api/logs/live-stream', (req, res) => {
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
    'X-Accel-Buffering': 'no',
  });

  let packetNo = 0;
  const localIP = '192.168.1.' + (100 + Math.floor(Math.random() * 50));

  const domains = [
    'google.com', 'github.com', 'stackoverflow.com', 'aws.amazon.com', 'cdn.cloudflare.com',
    'api.openai.com', 'fonts.googleapis.com', 'registry.npmjs.org', 'docker.io',
    'youtube.com', 'facebook.com', 'twitter.com', 'linkedin.com', 'reddit.com',
    'netflix.com', 'microsoft.com', 'apple.com', 'azure.com', 'slack.com',
    'zoom.us', 'dropbox.com', 'notion.so', 'figma.com', 'vercel.app',
  ];

  const suspiciousDomains = [
    'malware-c2.darknet.ru', '185.220.101.xx.tor-exit.net', 'free-cracked-tools.xyz',
    'update-flash-player.info', 'login-secure-bank.phishing.com', 'crypto-miner-pool.cc',
    'data-exfil.suspicious.io', 'ransomware-payment.onion.ws',
  ];

  const protocols = ['HTTP', 'HTTPS', 'DNS', 'TCP', 'UDP', 'ICMP', 'SSH', 'FTP'];
  const protoWeights = [15, 35, 20, 12, 8, 3, 4, 3];

  function weightedProto() {
    const total = protoWeights.reduce((a, b) => a + b, 0);
    let r = Math.random() * total;
    for (let i = 0; i < protocols.length; i++) {
      r -= protoWeights[i];
      if (r <= 0) return protocols[i];
    }
    return 'TCP';
  }

  function randomIP() {
    return [1, 2, 3, 4].map(() => Math.floor(Math.random() * 255)).join('.');
  }

  function randomPort() { return 1024 + Math.floor(Math.random() * 64000); }

  function generatePacket() {
    packetNo++;
    const proto = weightedProto();
    const isSuspicious = Math.random() < 0.08;
    const now = new Date();
    const domain = isSuspicious
      ? suspiciousDomains[Math.floor(Math.random() * suspiciousDomains.length)]
      : domains[Math.floor(Math.random() * domains.length)];

    let src = localIP, dst = randomIP(), srcPort = randomPort(), dstPort = 80;
    let info = '', length = 64 + Math.floor(Math.random() * 1400);
    let security = 'secure', threats = [], severity = 'info';

    switch (proto) {
      case 'HTTPS':
        dstPort = 443;
        const tlsVer = Math.random() > 0.15 ? 'TLS 1.3' : (Math.random() > 0.3 ? 'TLS 1.2' : 'TLS 1.0');
        info = `Client Hello → ${domain}:443 [${tlsVer}]`;
        security = tlsVer === 'TLS 1.0' ? 'warning' : 'secure';
        if (tlsVer === 'TLS 1.0') { threats.push('Deprecated TLS'); severity = 'low'; }
        length = 200 + Math.floor(Math.random() * 600);
        break;
      case 'HTTP':
        dstPort = 80;
        const methods = ['GET', 'POST', 'PUT', 'DELETE'];
        const method = methods[Math.floor(Math.random() * methods.length)];
        const paths = ['/', '/api/v1/data', '/index.html', '/login', '/search', '/assets/main.css'];
        info = `${method} ${paths[Math.floor(Math.random() * paths.length)]} HTTP/1.1 → ${domain}`;
        security = 'warning';
        if (isSuspicious) {
          const attackPayloads = [
            `${method} /api?q=1' OR 1=1-- → ${domain}`,
            `${method} /search?q=<script>alert(1)</script> → ${domain}`,
            `${method} /../../etc/passwd → ${domain}`,
            `${method} /wp-admin/ → ${domain}`,
          ];
          info = attackPayloads[Math.floor(Math.random() * attackPayloads.length)];
          security = 'danger';
          threats.push(info.includes('OR 1=1') ? 'SQL Injection' : info.includes('script') ? 'XSS Attack' : info.includes('etc/passwd') ? 'Path Traversal' : 'Reconnaissance');
          severity = 'high';
        }
        break;
      case 'DNS':
        dstPort = 53;
        dst = '8.8.8.8';
        const queryTypes = ['A', 'AAAA', 'MX', 'TXT', 'CNAME'];
        const qtype = queryTypes[Math.floor(Math.random() * queryTypes.length)];
        info = `Query ${qtype} ${domain}`;
        security = 'secure';
        if (isSuspicious) {
          info = `Query TXT ${suspiciousDomains[0]} [DNS Tunneling suspected]`;
          security = 'danger';
          threats.push('DNS Tunneling');
          severity = 'critical';
        }
        length = 40 + Math.floor(Math.random() * 100);
        break;
      case 'TCP':
        dstPort = [22, 80, 443, 3306, 5432, 8080, 8443][Math.floor(Math.random() * 7)];
        const flags = ['SYN', 'SYN-ACK', 'ACK', 'FIN', 'RST', 'PSH-ACK'];
        info = `${srcPort} → ${dstPort} [${flags[Math.floor(Math.random() * flags.length)]}] Seq=0 Win=65535`;
        if (isSuspicious && Math.random() > 0.5) {
          info = `Port Scan detected: ${srcPort} → multiple ports [SYN]`;
          threats.push('Port Scan');
          severity = 'medium';
          security = 'danger';
        }
        break;
      case 'UDP':
        dstPort = [53, 123, 161, 1900, 5353][Math.floor(Math.random() * 5)];
        info = `${srcPort} → ${dstPort} Len=${length}`;
        length = 20 + Math.floor(Math.random() * 200);
        break;
      case 'ICMP':
        info = Math.random() > 0.5 ? `Echo Request id=0x${Math.floor(Math.random() * 0xFFFF).toString(16)}` : `Echo Reply ttl=${32 + Math.floor(Math.random() * 200)}`;
        dstPort = 0;
        length = 64;
        break;
      case 'SSH':
        dstPort = 22;
        info = `SSH-2.0 Client: ${domain}`;
        security = 'secure';
        if (isSuspicious) {
          info = 'SSH Brute Force: Multiple failed auth attempts';
          threats.push('Brute Force');
          severity = 'high';
          security = 'danger';
        }
        break;
      case 'FTP':
        dstPort = 21;
        const ftpCmds = ['USER anonymous', 'LIST', 'RETR data.zip', 'STOR upload.bin'];
        info = `FTP ${ftpCmds[Math.floor(Math.random() * ftpCmds.length)]}`;
        security = 'warning';
        if (isSuspicious) {
          info = 'FTP STOR suspicious_payload.exe';
          threats.push('Suspicious Upload');
          severity = 'critical';
          security = 'danger';
        }
        break;
    }

    // Additional threat checks
    if (isSuspicious && threats.length === 0) {
      const extraThreats = [
        { type: 'Malware Beacon', detail: `C2 callback to ${domain}`, severity: 'critical' },
        { type: 'Data Exfiltration', detail: `Large outbound transfer to ${domain}`, severity: 'high' },
        { type: 'Crypto Mining', detail: `Mining pool connection to ${domain}`, severity: 'medium' },
      ];
      const t = extraThreats[Math.floor(Math.random() * extraThreats.length)];
      threats.push(t.type);
      info = t.detail;
      severity = t.severity;
      security = 'danger';
      length = 800 + Math.floor(Math.random() * 5000);
    }

    // Randomly flip src/dst for some packets (incoming vs outgoing)
    if (Math.random() > 0.6) {
      [src, dst] = [dst, src];
      [srcPort, dstPort] = [dstPort, srcPort];
    }

    return {
      no: packetNo,
      time: now.toISOString(),
      timeStr: now.toLocaleTimeString('en-US', { hour12: false, fractionalSecondDigits: 3 }),
      src: `${src}:${srcPort}`,
      dst: `${dst}:${dstPort}`,
      protocol: proto,
      length,
      info,
      security,
      threats,
      severity,
      domain,
      isSuspicious,
    };
  }

  const sendPacket = () => {
    if (res.destroyed) return;
    const pkt = generatePacket();
    res.write(`data: ${JSON.stringify(pkt)}\n\n`);
  };

  // Send 1-4 packets every 200-1200ms
  const interval = setInterval(() => {
    const batchSize = 1 + Math.floor(Math.random() * 3);
    for (let i = 0; i < batchSize; i++) {
      sendPacket();
    }
  }, 300 + Math.floor(Math.random() * 700));

  req.on('close', () => {
    clearInterval(interval);
  });
});

// ═══════════════════════════════════════════════════════════
// NEW MODULES — Link Tracker, Device, Network, DarkWeb, AttackMap, Metadata
// ═══════════════════════════════════════════════════════════

// --- LINK TRACKER ---
app.post('/api/tracker/create', (req, res) => {
  const { destination, customAlias, disguiseDomain } = req.body;
  if (!destination) return res.status(400).json({ error: 'Destination URL required.' });
  const link = linkTracker.createLink(destination, { customAlias, disguiseDomain });
  if (link.error) return res.status(400).json({ error: link.error });
  res.json(link);
});

app.get('/api/tracker/links', (req, res) => {
  res.json(linkTracker.getAllLinks());
});

app.get('/api/tracker/:id/visits', (req, res) => {
  const data = linkTracker.getLinkData(req.params.id);
  if (!data) return res.status(404).json({ error: 'Link not found' });
  res.json(data);
});

app.delete('/api/tracker/:id', (req, res) => {
  linkTracker.deleteLink(req.params.id);
  res.json({ ok: true });
});

app.get('/api/tracker/:id/live', (req, res) => {
  const data = linkTracker.getLinkData(req.params.id);
  if (!data) return res.status(404).json({ error: 'Link not found' });
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
    'X-Accel-Buffering': 'no',
  });
  linkTracker.addSSEClient(req.params.id, res);
  req.on('close', () => linkTracker.removeSSEClient(req.params.id, res));
});

app.post('/api/tracker/:id/visit', async (req, res) => {
  const id = req.params.id;
  const data = linkTracker.getLinkData(id);
  if (!data) return res.status(404).json({ error: 'Link not found' });
  const visitorInfo = {
    ...req.body,
    ip: req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress || '127.0.0.1',
  };
  const visit = await linkTracker.recordVisit(id, visitorInfo);
  res.json({ visitId: visit ? visit.id : null, destination: data.destination });
});

app.post('/api/tracker/:id/gps', (req, res) => {
  const { visitId, lat, lng, accuracy, altitude, speed } = req.body;
  linkTracker.updateGPS(req.params.id, visitId, { lat, lng, accuracy, altitude, speed });
  res.json({ ok: true });
});

// Alias-based visit recording (used by /s/:alias redirect page)
app.post('/api/tracker/alias/:alias/visit', async (req, res) => {
  const data = linkTracker.getLinkByAlias(req.params.alias);
  if (!data) return res.status(404).json({ error: 'Link not found' });
  const visitorInfo = {
    ...req.body,
    ip: req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress || '127.0.0.1',
  };
  const visit = await linkTracker.recordVisit(data.id, visitorInfo);
  res.json({ visitId: visit ? visit.id : null, destination: data.destination });
});

app.post('/api/tracker/alias/:alias/gps', (req, res) => {
  const data = linkTracker.getLinkByAlias(req.params.alias);
  if (!data) return res.status(404).json({ error: 'Link not found' });
  const { visitId, lat, lng, accuracy, altitude, speed } = req.body;
  linkTracker.updateGPS(data.id, visitId, { lat, lng, accuracy, altitude, speed });
  res.json({ ok: true });
});

// Serve the tracking page (by ID)
app.get('/t/:id', (req, res) => {
  const data = linkTracker.getLinkData(req.params.id);
  if (!data) return res.status(404).send('Link not found');
  res.sendFile(path.join(__dirname, 'public', 'tracked.html'));
});

// Serve the tracking page (by alias — the "shortened" link)
app.get('/s/:alias', (req, res) => {
  const data = linkTracker.getLinkByAlias(req.params.alias);
  if (!data) return res.status(404).send('Link not found');
  res.sendFile(path.join(__dirname, 'public', 'tracked.html'));
});

// --- DEVICE SECURITY ---
app.post('/api/device/scan', (req, res) => {
  const result = analyzeDeviceData(req.body);
  res.json(result);
});

app.post('/api/device/headers', async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: 'URL required' });
  const result = await checkSecurityHeaders(url);
  res.json(result);
});

// --- NETWORK SCANNER ---
app.post('/api/network/dns-leak', async (req, res) => {
  const { domain } = req.body;
  const result = await dnsLeakTest(domain || 'example.com');
  res.json(result);
});

app.post('/api/network/port-scan', async (req, res) => {
  const { target } = req.body;
  const result = await portScan(target || 'localhost');
  res.json(result);
});

app.post('/api/network/ssl-check', async (req, res) => {
  const { hostname } = req.body;
  if (!hostname) return res.status(400).json({ error: 'Hostname required' });
  const result = await sslCheck(hostname);
  res.json(result);
});

app.get('/api/network/latency', async (req, res) => {
  const result = await latencyTest();
  res.json(result);
});

// --- DARK WEB MONITOR ---
app.post('/api/darkweb/check', (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email required' });
  const result = checkDarkWeb(email);
  res.json(result);
});

// --- ATTACK MAP ---
app.get('/api/attackmap/stream', (req, res) => {
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
    'X-Accel-Buffering': 'no',
  });
  const interval = setInterval(() => {
    if (res.destroyed) { clearInterval(interval); return; }
    const batch = generateAttackBatch(1 + Math.floor(Math.random() * 3));
    res.write(`data: ${JSON.stringify(batch)}\n\n`);
  }, 800 + Math.floor(Math.random() * 600));
  req.on('close', () => clearInterval(interval));
});

// ─────────────────────────────────────────────
// Serve Pages
// ─────────────────────────────────────────────
app.get('/osint', (req, res) => res.sendFile(path.join(__dirname, 'public', 'osint.html')));
app.get('/logs', (req, res) => res.sendFile(path.join(__dirname, 'public', 'logs.html')));
app.get('/tracker', (req, res) => res.sendFile(path.join(__dirname, 'public', 'tracker.html')));
app.get('/device', (req, res) => res.sendFile(path.join(__dirname, 'public', 'device.html')));
app.get('/network', (req, res) => res.sendFile(path.join(__dirname, 'public', 'network.html')));
app.get('/darkweb', (req, res) => res.sendFile(path.join(__dirname, 'public', 'darkweb.html')));
app.get('/attackmap', (req, res) => res.sendFile(path.join(__dirname, 'public', 'attackmap.html')));
app.get('/metadata', (req, res) => res.sendFile(path.join(__dirname, 'public', 'metadata.html')));

// ─────────────────────────────────────────────
// Serve SPA (catch-all)
// ─────────────────────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`\n🛡️  CyberDashboard server running on http://localhost:${PORT}\n`);
});
