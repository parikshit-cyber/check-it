/**
 * Live Cyber Attack Map Engine
 * Generates realistic simulated cyber attack data for visualization
 */

// Major cities with coordinates for attack source/target
const LOCATIONS = [
    { city: 'Beijing', country: 'China', cc: 'CN', lat: 39.9042, lng: 116.4074 },
    { city: 'Moscow', country: 'Russia', cc: 'RU', lat: 55.7558, lng: 37.6173 },
    { city: 'Washington DC', country: 'USA', cc: 'US', lat: 38.9072, lng: -77.0369 },
    { city: 'New York', country: 'USA', cc: 'US', lat: 40.7128, lng: -74.006 },
    { city: 'London', country: 'UK', cc: 'GB', lat: 51.5074, lng: -0.1278 },
    { city: 'Berlin', country: 'Germany', cc: 'DE', lat: 52.52, lng: 13.405 },
    { city: 'Tokyo', country: 'Japan', cc: 'JP', lat: 35.6762, lng: 139.6503 },
    { city: 'Seoul', country: 'South Korea', cc: 'KR', lat: 37.5665, lng: 126.978 },
    { city: 'Mumbai', country: 'India', cc: 'IN', lat: 19.076, lng: 72.8777 },
    { city: 'São Paulo', country: 'Brazil', cc: 'BR', lat: -23.5558, lng: -46.6396 },
    { city: 'Sydney', country: 'Australia', cc: 'AU', lat: -33.8688, lng: 151.2093 },
    { city: 'Paris', country: 'France', cc: 'FR', lat: 48.8566, lng: 2.3522 },
    { city: 'Tehran', country: 'Iran', cc: 'IR', lat: 35.6892, lng: 51.389 },
    { city: 'Pyongyang', country: 'North Korea', cc: 'KP', lat: 39.0392, lng: 125.7625 },
    { city: 'Lagos', country: 'Nigeria', cc: 'NG', lat: 6.5244, lng: 3.3792 },
    { city: 'Kyiv', country: 'Ukraine', cc: 'UA', lat: 50.4501, lng: 30.5234 },
    { city: 'Singapore', country: 'Singapore', cc: 'SG', lat: 1.3521, lng: 103.8198 },
    { city: 'Toronto', country: 'Canada', cc: 'CA', lat: 43.6532, lng: -79.3832 },
    { city: 'Dubai', country: 'UAE', cc: 'AE', lat: 25.2048, lng: 55.2708 },
    { city: 'Amsterdam', country: 'Netherlands', cc: 'NL', lat: 52.3676, lng: 4.9041 },
    { city: 'Tel Aviv', country: 'Israel', cc: 'IL', lat: 32.0853, lng: 34.7818 },
    { city: 'Stockholm', country: 'Sweden', cc: 'SE', lat: 59.3293, lng: 18.0686 },
    { city: 'Bucharest', country: 'Romania', cc: 'RO', lat: 44.4268, lng: 26.1025 },
    { city: 'Jakarta', country: 'Indonesia', cc: 'ID', lat: -6.2088, lng: 106.8456 },
    { city: 'Mexico City', country: 'Mexico', cc: 'MX', lat: 19.4326, lng: -99.1332 },
];

// Attack type probabilities (higher = more frequent)
const ATTACK_TYPES = [
    { type: 'DDoS', weight: 25, color: '#ff3366', severity: 'high', icon: '💥' },
    { type: 'Brute Force', weight: 20, color: '#ff6633', severity: 'medium', icon: '🔓' },
    { type: 'Phishing', weight: 18, color: '#ffcc00', severity: 'medium', icon: '🎣' },
    { type: 'Ransomware', weight: 10, color: '#ff0044', severity: 'critical', icon: '💀' },
    { type: 'SQL Injection', weight: 12, color: '#ff9900', severity: 'high', icon: '💉' },
    { type: 'XSS', weight: 8, color: '#ff66cc', severity: 'medium', icon: '🕷️' },
    { type: 'Malware', weight: 15, color: '#cc00ff', severity: 'high', icon: '🦠' },
    { type: 'Port Scan', weight: 22, color: '#00ccff', severity: 'low', icon: '📡' },
    { type: 'Data Exfiltration', weight: 6, color: '#ff0000', severity: 'critical', icon: '📤' },
    { type: 'Zero Day', weight: 3, color: '#ff0066', severity: 'critical', icon: '⚡' },
    { type: 'Man-in-the-Middle', weight: 5, color: '#ff6600', severity: 'high', icon: '👤' },
    { type: 'DNS Hijacking', weight: 7, color: '#00ff99', severity: 'high', icon: '🌐' },
];

// Top attacking country weights (some countries attack more in simulation)
const SOURCE_WEIGHTS = {
    CN: 20, RU: 18, US: 12, KP: 8, IR: 7, NG: 6, BR: 5, RO: 5,
};

// Top target country weights
const TARGET_WEIGHTS = {
    US: 22, GB: 12, DE: 10, JP: 8, FR: 7, KR: 6, AU: 5, IN: 5, CA: 5, SG: 4,
};

const totalAttackWeight = ATTACK_TYPES.reduce((s, a) => s + a.weight, 0);

function pickWeighted(items, weightFn) {
    const total = items.reduce((s, i) => s + weightFn(i), 0);
    let r = Math.random() * total;
    for (const item of items) {
        r -= weightFn(item);
        if (r <= 0) return item;
    }
    return items[items.length - 1];
}

function randomIP() {
    return `${1 + Math.floor(Math.random() * 254)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${1 + Math.floor(Math.random() * 254)}`;
}

/**
 * Generate a single attack event
 */
function generateAttack() {
    const attack = pickWeighted(ATTACK_TYPES, (a) => a.weight);

    // Pick source — weighted toward known attacker countries
    const source = pickWeighted(LOCATIONS, (loc) => SOURCE_WEIGHTS[loc.cc] || 2);

    // Pick target — weighted toward common targets, must be different from source
    let target;
    do {
        target = pickWeighted(LOCATIONS, (loc) => TARGET_WEIGHTS[loc.cc] || 2);
    } while (target.city === source.city);

    return {
        id: Date.now().toString(36) + Math.random().toString(36).substring(2, 6),
        type: attack.type,
        color: attack.color,
        severity: attack.severity,
        icon: attack.icon,
        source: {
            city: source.city,
            country: source.country,
            cc: source.cc,
            lat: source.lat + (Math.random() - 0.5) * 2,
            lng: source.lng + (Math.random() - 0.5) * 2,
            ip: randomIP(),
        },
        target: {
            city: target.city,
            country: target.country,
            cc: target.cc,
            lat: target.lat + (Math.random() - 0.5) * 2,
            lng: target.lng + (Math.random() - 0.5) * 2,
            ip: randomIP(),
        },
        timestamp: new Date().toISOString(),
        port: [21, 22, 25, 53, 80, 443, 445, 993, 3306, 3389, 8080][Math.floor(Math.random() * 11)],
    };
}

/**
 * Generate a batch of attacks
 */
function generateBatch(count = 5) {
    const attacks = [];
    for (let i = 0; i < count; i++) {
        attacks.push(generateAttack());
    }
    return attacks;
}

/**
 * Get attack type statistics
 */
function getAttackStats() {
    return ATTACK_TYPES.map((a) => ({
        type: a.type,
        color: a.color,
        icon: a.icon,
        severity: a.severity,
        relativeFrequency: Math.round((a.weight / totalAttackWeight) * 100),
    }));
}

module.exports = { generateAttack, generateBatch, getAttackStats, LOCATIONS };
