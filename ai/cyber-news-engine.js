/**
 * Cyber News Engine — Real-Time RSS Feed Aggregator
 * Fetches live cybersecurity news from major RSS feeds,
 * auto-classifies categories, and extracts geo-locations.
 *
 * No API keys required. Uses native Node.js http/https.
 */

const https = require('https');
const http = require('http');

// ── RSS Feed Sources ──
const RSS_FEEDS = [
    { name: 'The Hacker News', url: 'https://feeds.feedburner.com/TheHackersNews' },
    { name: 'BleepingComputer', url: 'https://www.bleepingcomputer.com/feed/' },
    { name: 'Dark Reading', url: 'https://www.darkreading.com/rss.xml' },
    { name: 'SecurityWeek', url: 'https://www.securityweek.com/feed/' },
    { name: 'The Register Security', url: 'https://www.theregister.com/security/headlines.atom' },
    { name: 'Krebs on Security', url: 'https://krebsonsecurity.com/feed/' },
];

// ── Category keyword map ──
const CATEGORY_KEYWORDS = {
    'Ransomware': ['ransomware', 'ransom', 'lockbit', 'blackcat', 'conti', 'encrypt'],
    'Phishing': ['phishing', 'phish', 'spear-phishing', 'credential theft', 'social engineering'],
    'Malware': ['malware', 'trojan', 'worm', 'virus', 'botnet', 'infostealer', 'stealer', 'loader'],
    'Vulnerability': ['vulnerability', 'CVE-', 'cve-', 'zero-day', '0-day', 'patch', 'exploit', 'RCE', 'buffer overflow', 'flaw'],
    'Data Breach': ['breach', 'data leak', 'leaked', 'exposed', 'stolen data', 'compromised'],
    'APT': ['APT', 'state-sponsored', 'nation-state', 'espionage', 'advanced persistent', 'lazarus', 'cozy bear', 'fancy bear'],
    'DDoS': ['DDoS', 'denial of service', 'ddos', 'botnet attack'],
    'AI Security': ['AI', 'artificial intelligence', 'machine learning', 'deepfake', 'LLM', 'ChatGPT'],
    'Supply Chain': ['supply chain', 'supply-chain', 'dependency', 'package', 'npm', 'pypi'],
    'Privacy': ['privacy', 'GDPR', 'surveillance', 'tracking', 'data protection'],
    'IoT': ['IoT', 'smart device', 'firmware', 'embedded', 'OT', 'SCADA', 'ICS'],
    'Cloud': ['cloud', 'AWS', 'Azure', 'GCP', 'misconfigured', 'S3 bucket', 'kubernetes'],
    'Encryption': ['encryption', 'cryptograph', 'TLS', 'SSL', 'quantum', 'post-quantum'],
    'Policy': ['regulation', 'legislation', 'government', 'federal', 'CISA', 'NSA', 'FBI', 'policy', 'executive order'],
};

// ── Location extraction: keyword → coordinates ──
const LOCATION_MAP = {
    // Countries
    'russia': { city: 'Moscow', country: 'Russia', lat: 55.75, lng: 37.62 },
    'china': { city: 'Beijing', country: 'China', lat: 39.91, lng: 116.40 },
    'iran': { city: 'Tehran', country: 'Iran', lat: 35.69, lng: 51.39 },
    'north korea': { city: 'Pyongyang', country: 'North Korea', lat: 39.03, lng: 125.75 },
    'ukraine': { city: 'Kyiv', country: 'Ukraine', lat: 50.45, lng: 30.52 },
    'japan': { city: 'Tokyo', country: 'Japan', lat: 35.68, lng: 139.69 },
    'india': { city: 'New Delhi', country: 'India', lat: 28.61, lng: 77.21 },
    'germany': { city: 'Berlin', country: 'Germany', lat: 52.52, lng: 13.41 },
    'uk': { city: 'London', country: 'UK', lat: 51.51, lng: -0.13 },
    'britain': { city: 'London', country: 'UK', lat: 51.51, lng: -0.13 },
    'australia': { city: 'Sydney', country: 'Australia', lat: -33.87, lng: 151.21 },
    'brazil': { city: 'São Paulo', country: 'Brazil', lat: -23.55, lng: -46.63 },
    'canada': { city: 'Ottawa', country: 'Canada', lat: 45.42, lng: -75.70 },
    'france': { city: 'Paris', country: 'France', lat: 48.86, lng: 2.35 },
    'israel': { city: 'Tel Aviv', country: 'Israel', lat: 32.09, lng: 34.78 },
    'south korea': { city: 'Seoul', country: 'South Korea', lat: 37.57, lng: 126.98 },
    'singapore': { city: 'Singapore', country: 'Singapore', lat: 1.35, lng: 103.82 },
    'netherlands': { city: 'Amsterdam', country: 'Netherlands', lat: 52.37, lng: 4.90 },

    // Cities
    'washington': { city: 'Washington D.C.', country: 'USA', lat: 38.91, lng: -77.04 },
    'new york': { city: 'New York', country: 'USA', lat: 40.71, lng: -74.00 },
    'san francisco': { city: 'San Francisco', country: 'USA', lat: 37.77, lng: -122.42 },
    'london': { city: 'London', country: 'UK', lat: 51.51, lng: -0.13 },
    'beijing': { city: 'Beijing', country: 'China', lat: 39.91, lng: 116.40 },
    'moscow': { city: 'Moscow', country: 'Russia', lat: 55.75, lng: 37.62 },
    'tokyo': { city: 'Tokyo', country: 'Japan', lat: 35.68, lng: 139.69 },
    'dubai': { city: 'Dubai', country: 'UAE', lat: 25.20, lng: 55.27 },
    'mumbai': { city: 'Mumbai', country: 'India', lat: 19.07, lng: 72.88 },
    'hong kong': { city: 'Hong Kong', country: 'China', lat: 22.32, lng: 114.17 },

    // Agencies / orgs that imply US location
    'fbi': { city: 'Washington D.C.', country: 'USA', lat: 38.91, lng: -77.04 },
    'cisa': { city: 'Washington D.C.', country: 'USA', lat: 38.91, lng: -77.04 },
    'nsa': { city: 'Washington D.C.', country: 'USA', lat: 38.91, lng: -77.04 },
    'nist': { city: 'Washington D.C.', country: 'USA', lat: 38.91, lng: -77.04 },
    'europol': { city: 'The Hague', country: 'Netherlands', lat: 52.08, lng: 4.31 },
    'interpol': { city: 'Lyon', country: 'France', lat: 45.76, lng: 4.84 },

    // Threat groups that imply origin
    'lazarus': { city: 'Pyongyang', country: 'North Korea', lat: 39.03, lng: 125.75 },
    'apt28': { city: 'Moscow', country: 'Russia', lat: 55.75, lng: 37.62 },
    'apt29': { city: 'Moscow', country: 'Russia', lat: 55.75, lng: 37.62 },
    'fancy bear': { city: 'Moscow', country: 'Russia', lat: 55.75, lng: 37.62 },
    'cozy bear': { city: 'Moscow', country: 'Russia', lat: 55.75, lng: 37.62 },
    'apt41': { city: 'Chengdu', country: 'China', lat: 30.57, lng: 104.07 },
};

// Default global locations when no specific geo is detected
const GLOBAL_LOCATIONS = [
    { city: 'Washington D.C.', country: 'USA', lat: 38.91, lng: -77.04 },
    { city: 'London', country: 'UK', lat: 51.51, lng: -0.13 },
    { city: 'San Francisco', country: 'USA', lat: 37.77, lng: -122.42 },
    { city: 'Frankfurt', country: 'Germany', lat: 50.11, lng: 8.68 },
    { city: 'Singapore', country: 'Singapore', lat: 1.35, lng: 103.82 },
    { city: 'Tokyo', country: 'Japan', lat: 35.68, lng: 139.69 },
    { city: 'Sydney', country: 'Australia', lat: -33.87, lng: 151.21 },
    { city: 'Tel Aviv', country: 'Israel', lat: 32.09, lng: 34.78 },
];

// ── Cache ──
let cachedNews = null;
let cacheExpiry = 0;
const CACHE_DURATION_MS = 5 * 60 * 1000; // 5 minutes

/**
 * Fetch a URL and return the raw text body.
 */
function fetchText(url, timeoutMs = 8000) {
    const lib = url.startsWith('https') ? https : http;
    return new Promise((resolve, reject) => {
        const req = lib.get(url, { timeout: timeoutMs }, (response) => {
            // Follow redirects
            if (response.statusCode >= 300 && response.statusCode < 400 && response.headers.location) {
                return fetchText(response.headers.location, timeoutMs).then(resolve).catch(reject);
            }
            if (response.statusCode !== 200) {
                return reject(new Error(`HTTP ${response.statusCode}`));
            }
            let body = '';
            response.on('data', chunk => body += chunk);
            response.on('end', () => resolve(body));
            response.on('error', reject);
        });
        req.on('error', reject);
        req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')); });
    });
}

/**
 * Parse RSS/Atom XML into an array of items.
 * Uses regex — no external XML parser dependency needed.
 */
function parseRSSItems(xml) {
    const items = [];

    // Try RSS <item> tags
    const rssPattern = /<item>([\s\S]*?)<\/item>/gi;
    let match;

    while ((match = rssPattern.exec(xml)) !== null) {
        const block = match[1];
        const title = extractTag(block, 'title');
        const link = extractTag(block, 'link') || extractAtomLink(block);
        const description = stripHTML(extractTag(block, 'description') || extractTag(block, 'content:encoded') || '');
        const pubDate = extractTag(block, 'pubDate') || extractTag(block, 'dc:date');

        if (title) {
            items.push({ title: stripHTML(title).trim(), link, description: description.slice(0, 200), pubDate });
        }
    }

    // If no RSS items, try Atom <entry> tags
    if (items.length === 0) {
        const atomPattern = /<entry>([\s\S]*?)<\/entry>/gi;
        while ((match = atomPattern.exec(xml)) !== null) {
            const block = match[1];
            const title = extractTag(block, 'title');
            const link = extractAtomLink(block) || extractTag(block, 'link');
            const description = stripHTML(extractTag(block, 'summary') || extractTag(block, 'content') || '');
            const pubDate = extractTag(block, 'published') || extractTag(block, 'updated');

            if (title) {
                items.push({ title: stripHTML(title).trim(), link, description: description.slice(0, 200), pubDate });
            }
        }
    }

    return items;
}

function extractTag(xml, tagName) {
    // Handle CDATA sections
    const cdataPattern = new RegExp(`<${tagName}[^>]*>\\s*<!\\[CDATA\\[([\\s\\S]*?)\\]\\]>\\s*</${tagName}>`, 'i');
    const cdataMatch = xml.match(cdataPattern);
    if (cdataMatch) return cdataMatch[1];

    const pattern = new RegExp(`<${tagName}[^>]*>([\\s\\S]*?)</${tagName}>`, 'i');
    const m = xml.match(pattern);
    return m ? m[1].trim() : '';
}

function extractAtomLink(block) {
    const m = block.match(/<link[^>]*href=["']([^"']+)["'][^>]*\/?>/i);
    return m ? m[1] : '';
}

function stripHTML(str) {
    return str.replace(/<[^>]+>/g, '').replace(/&amp;/g, '&').replace(/&lt;/g, '<')
        .replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#39;/g, "'")
        .replace(/&nbsp;/g, ' ').trim();
}

/**
 * Detect the security category from article title + description.
 */
function detectCategory(title, description) {
    const text = (title + ' ' + description).toLowerCase();

    for (const [category, keywords] of Object.entries(CATEGORY_KEYWORDS)) {
        for (const kw of keywords) {
            if (text.includes(kw.toLowerCase())) {
                return category;
            }
        }
    }

    return 'Cybersecurity'; // Generic fallback
}

/**
 * Extract the most likely geographic location from article text.
 */
function extractLocation(title, description) {
    const text = (title + ' ' + description).toLowerCase();

    // Check location keywords (longer phrases first to match "north korea" before "korea")
    const sortedKeys = Object.keys(LOCATION_MAP).sort((a, b) => b.length - a.length);

    for (const keyword of sortedKeys) {
        if (text.includes(keyword)) {
            return LOCATION_MAP[keyword];
        }
    }

    // No location found — assign a global tech hub
    return GLOBAL_LOCATIONS[Math.floor(Math.random() * GLOBAL_LOCATIONS.length)];
}

/**
 * Fetch all RSS feeds in parallel, deduplicate, sort by date.
 */
async function fetchAllFeeds() {
    const results = await Promise.allSettled(
        RSS_FEEDS.map(async (feed) => {
            try {
                const xml = await fetchText(feed.url);
                const items = parseRSSItems(xml);
                return items.map(item => ({ ...item, source: feed.name }));
            } catch (err) {
                console.warn(`[News] Failed to fetch ${feed.name}: ${err.message}`);
                return [];
            }
        })
    );

    // Flatten all successful results
    const allItems = [];
    for (const result of results) {
        if (result.status === 'fulfilled' && result.value.length) {
            allItems.push(...result.value);
        }
    }

    return allItems;
}

/**
 * Main function: get live cybersecurity news.
 * Returns an array matching the frontend format.
 */
async function fetchCyberNews() {
    // Return cache if still fresh
    if (cachedNews && Date.now() < cacheExpiry) {
        return cachedNews;
    }

    console.log('[News] Fetching live RSS feeds...');

    const rawItems = await fetchAllFeeds();

    if (rawItems.length === 0) {
        console.warn('[News] All RSS feeds failed — no live news available');
        return cachedNews || []; // Return stale cache or empty
    }

    // Deduplicate by title (case-insensitive)
    const seen = new Set();
    const unique = rawItems.filter(item => {
        const key = item.title.toLowerCase();
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
    });

    // Convert to frontend format
    const newsItems = unique.map(item => {
        const category = detectCategory(item.title, item.description);
        const location = extractLocation(item.title, item.description);

        return {
            id: Date.now().toString(36) + Math.random().toString(36).slice(2, 7),
            title: item.title,
            summary: item.description || item.title,
            source: item.source,
            category,
            city: location.city,
            country: location.country,
            lat: location.lat,
            lng: location.lng,
            timestamp: item.pubDate ? new Date(item.pubDate).toISOString() : new Date().toISOString(),
            url: item.link || '#',
        };
    });

    // Sort by date (newest first) and take top 30
    newsItems.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
    const finalNews = newsItems.slice(0, 30);

    // Cache results
    cachedNews = finalNews;
    cacheExpiry = Date.now() + CACHE_DURATION_MS;

    console.log(`[News] Fetched ${finalNews.length} real articles from RSS feeds`);
    return finalNews;
}

module.exports = { fetchCyberNews };
