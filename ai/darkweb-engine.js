/**
 * Dark Web Monitor Engine
 * Simulates breach checking for emails using heuristic breach database.
 * In production, integrate with HaveIBeenPwned API.
 */

const crypto = require('crypto');

// Simulated breach database — realistic breach data
const BREACH_DATABASE = [
    {
        name: 'LinkedIn',
        date: '2021-06-22',
        records: 700000000,
        dataTypes: ['email', 'name', 'phone', 'employment', 'location'],
        severity: 'high',
        description: 'Massive scraping incident exposed 700M user profiles',
    },
    {
        name: 'Facebook',
        date: '2021-04-03',
        records: 533000000,
        dataTypes: ['email', 'name', 'phone', 'location', 'birthdate', 'gender'],
        severity: 'critical',
        description: 'Phone numbers and personal data of 533M users leaked',
    },
    {
        name: 'Adobe',
        date: '2013-10-04',
        records: 153000000,
        dataTypes: ['email', 'password', 'name', 'username'],
        severity: 'critical',
        description: 'Encrypted passwords leaked along with password hints in plaintext',
    },
    {
        name: 'Canva',
        date: '2019-05-24',
        records: 137000000,
        dataTypes: ['email', 'name', 'username', 'location'],
        severity: 'medium',
        description: 'Usernames and email addresses exposed; passwords were bcrypt hashed',
    },
    {
        name: 'Dropbox',
        date: '2016-08-30',
        records: 68648009,
        dataTypes: ['email', 'password'],
        severity: 'critical',
        description: 'Email addresses and bcrypt/SHA-1 hashed passwords from 2012 breach',
    },
    {
        name: 'Twitter / X',
        date: '2023-01-05',
        records: 209000000,
        dataTypes: ['email', 'name', 'username', 'phone'],
        severity: 'high',
        description: 'Email addresses linked to Twitter accounts via API vulnerability',
    },
    {
        name: 'MySpace',
        date: '2016-05-27',
        records: 360000000,
        dataTypes: ['email', 'password', 'username'],
        severity: 'critical',
        description: 'Massive dump with SHA-1 hashed passwords (no salt)',
    },
    {
        name: 'Zynga',
        date: '2019-09-12',
        records: 173000000,
        dataTypes: ['email', 'password', 'username', 'phone'],
        severity: 'high',
        description: 'Words With Friends player data exposed including hashed passwords',
    },
    {
        name: 'Exactis',
        date: '2018-06-27',
        records: 340000000,
        dataTypes: ['email', 'name', 'phone', 'address', 'interests', 'habits'],
        severity: 'critical',
        description: 'Marketing firm exposed nearly every US citizen\'s personal data',
    },
    {
        name: 'Wattpad',
        date: '2020-06-29',
        records: 270000000,
        dataTypes: ['email', 'password', 'username', 'name', 'birthdate', 'ip'],
        severity: 'high',
        description: 'Bcrypt-hashed passwords and personal data of 270M users',
    },
    {
        name: 'Dubsmash',
        date: '2018-12-01',
        records: 162000000,
        dataTypes: ['email', 'password', 'username', 'name', 'phone'],
        severity: 'high',
        description: 'Part of the "Collection #1" mega-breach selling on dark web',
    },
    {
        name: 'Marriott (Starwood)',
        date: '2018-11-30',
        records: 500000000,
        dataTypes: ['email', 'name', 'phone', 'passport', 'address', 'payment'],
        severity: 'critical',
        description: 'Guest records including encrypted passport and credit card numbers',
    },
    {
        name: 'Equifax',
        date: '2017-09-07',
        records: 147900000,
        dataTypes: ['name', 'ssn', 'birthdate', 'address', 'drivers_license'],
        severity: 'critical',
        description: 'Social Security numbers and financial data of nearly half the US',
    },
    {
        name: 'Under Armour (MyFitnessPal)',
        date: '2018-03-29',
        records: 150000000,
        dataTypes: ['email', 'password', 'username'],
        severity: 'high',
        description: 'SHA-1 and bcrypt hashed passwords exposed',
    },
    {
        name: 'Capital One',
        date: '2019-07-29',
        records: 106000000,
        dataTypes: ['name', 'address', 'phone', 'email', 'birthdate', 'income', 'ssn'],
        severity: 'critical',
        description: 'AWS misconfiguration exposed credit applications and SSNs',
    },
];

/**
 * Check an email against the simulated breach database
 * Uses deterministic hashing so same email always gets same results
 */
function checkEmail(email) {
    const normalized = email.toLowerCase().trim();
    const hash = crypto.createHash('sha256').update(normalized).digest('hex');

    // Use hash to deterministically select breaches (2-7 breaches per email)
    const hashNum = parseInt(hash.substring(0, 8), 16);
    const breachCount = 2 + (hashNum % 6);

    const selectedBreaches = [];
    for (let i = 0; i < breachCount; i++) {
        const idx = parseInt(hash.substring(i * 2, i * 2 + 4), 16) % BREACH_DATABASE.length;
        const breach = BREACH_DATABASE[idx];
        if (!selectedBreaches.find((b) => b.name === breach.name)) {
            selectedBreaches.push({ ...breach });
        }
    }

    // Sort by date (newest first)
    selectedBreaches.sort((a, b) => new Date(b.date) - new Date(a.date));

    // Calculate exposed data types
    const allDataTypes = new Set();
    selectedBreaches.forEach((b) => b.dataTypes.forEach((d) => allDataTypes.add(d)));

    // Calculate risk score
    let riskScore = 0;
    selectedBreaches.forEach((b) => {
        if (b.severity === 'critical') riskScore += 30;
        else if (b.severity === 'high') riskScore += 20;
        else if (b.severity === 'medium') riskScore += 10;
        else riskScore += 5;
    });
    riskScore = Math.min(100, riskScore);

    const hasPasswordLeak = selectedBreaches.some((b) => b.dataTypes.includes('password'));
    const hasSsnLeak = selectedBreaches.some((b) => b.dataTypes.includes('ssn'));
    const hasPaymentLeak = selectedBreaches.some((b) => b.dataTypes.includes('payment'));

    // Generate recommendations
    const recommendations = [];
    if (hasPasswordLeak) {
        recommendations.push({
            priority: 'critical',
            action: 'Change passwords immediately',
            detail: 'Your password hash was exposed. Change passwords on all accounts that used the same password.',
        });
        recommendations.push({
            priority: 'high',
            action: 'Enable Two-Factor Authentication (2FA)',
            detail: 'Add 2FA to all accounts, especially email and financial services.',
        });
    }
    if (hasSsnLeak) {
        recommendations.push({
            priority: 'critical',
            action: 'Freeze your credit',
            detail: 'Contact Equifax, Experian, and TransUnion to freeze credit and prevent identity theft.',
        });
    }
    if (hasPaymentLeak) {
        recommendations.push({
            priority: 'critical',
            action: 'Monitor financial accounts',
            detail: 'Check bank and credit card statements. Consider requesting new card numbers.',
        });
    }
    recommendations.push({
        priority: 'medium',
        action: 'Use a password manager',
        detail: 'Generate unique, strong passwords for every account.',
    });
    recommendations.push({
        priority: 'low',
        action: 'Monitor for identity theft',
        detail: 'Set up alerts on credit monitoring services.',
    });

    let riskLevel;
    if (riskScore >= 80) riskLevel = 'critical';
    else if (riskScore >= 60) riskLevel = 'high';
    else if (riskScore >= 40) riskLevel = 'medium';
    else riskLevel = 'low';

    return {
        email: normalized,
        breachCount: selectedBreaches.length,
        breaches: selectedBreaches,
        exposedDataTypes: [...allDataTypes],
        riskScore,
        riskLevel,
        hasPasswordLeak,
        hasSsnLeak,
        hasPaymentLeak,
        recommendations,
        totalExposedRecords: selectedBreaches.reduce((s, b) => s + b.records, 0),
        firstBreach: selectedBreaches[selectedBreaches.length - 1]?.date || null,
        lastBreach: selectedBreaches[0]?.date || null,
        timestamp: new Date().toISOString(),
    };
}

module.exports = { checkEmail };
