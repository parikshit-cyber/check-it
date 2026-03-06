/**
 * CHECK-IT OSINT — Frontend Application Logic
 * Handles tab switching, API calls, Chart.js rendering, and results display
 */

(function () {
    'use strict';

    const $ = (sel) => document.querySelector(sel);
    const $$ = (sel) => document.querySelectorAll(sel);

    // ── Elements ──
    const liveClock = $('#live-clock');
    const osintTabs = $$('.osint-tab');
    const osintForm = $('#osint-form');
    const osintInput = $('#osint-input');
    const osintInputIcon = $('#osint-input-icon');
    const osintBtn = $('#osint-btn');
    const osintResults = $('#osint-results');
    const themeToggle = $('#theme-toggle');

    let currentType = 'username';
    let chartMain = null;
    let chartSecondary = null;

    const TYPE_CONFIG = {
        username: { icon: '👤', placeholder: 'Enter username to investigate...', endpoint: '/api/osint/username', field: 'username' },
        website: { icon: '🌐', placeholder: 'Enter website URL (e.g. github.com)...', endpoint: '/api/osint/website', field: 'url' },
        email: { icon: '📧', placeholder: 'Enter email address...', endpoint: '/api/osint/email', field: 'email' },
        phone: { icon: '📱', placeholder: 'Enter phone number (e.g. +1234567890)...', endpoint: '/api/osint/phone', field: 'phone' },
        domain: { icon: '🔗', placeholder: 'Enter domain name (e.g. google.com)...', endpoint: '/api/osint/domain', field: 'domain' },
    };

    // ═══════════════ CLOCK ═══════════════
    function updateClock() {
        const now = new Date();
        liveClock.textContent = [now.getHours(), now.getMinutes(), now.getSeconds()]
            .map(v => String(v).padStart(2, '0')).join(':');
    }
    setInterval(updateClock, 1000);
    updateClock();

    // ═══════════════ THEME TOGGLE ═══════════════
    function setTheme(theme) {
        document.documentElement.setAttribute('data-theme', theme);
        localStorage.setItem('checkit-theme', theme);
        themeToggle.classList.toggle('light', theme === 'light');
    }

    const savedTheme = localStorage.getItem('checkit-theme') || 'dark';
    setTheme(savedTheme);

    themeToggle.addEventListener('click', () => {
        const current = document.documentElement.getAttribute('data-theme');
        setTheme(current === 'dark' ? 'light' : 'dark');
    });

    // ═══════════════ PARTICLES ═══════════════
    (function spawnParticles() {
        const container = $('#particles');
        for (let i = 0; i < 30; i++) {
            const p = document.createElement('div');
            p.className = 'particle';
            p.style.left = Math.random() * 100 + '%';
            p.style.animationDuration = (8 + Math.random() * 15) + 's';
            p.style.animationDelay = (Math.random() * 10) + 's';
            const s = (1 + Math.random() * 2) + 'px';
            p.style.width = s; p.style.height = s;
            container.appendChild(p);
        }
    })();

    // ═══════════════ TAB SWITCHING ═══════════════
    osintTabs.forEach(tab => {
        tab.addEventListener('click', () => {
            const type = tab.dataset.type;
            if (type === currentType) return;
            currentType = type;

            osintTabs.forEach(t => t.classList.remove('active'));
            tab.classList.add('active');

            const config = TYPE_CONFIG[type];
            osintInput.placeholder = config.placeholder;
            osintInputIcon.textContent = config.icon;
            osintInput.value = '';
            osintInput.focus();
        });
    });

    // ═══════════════ FORM SUBMIT ═══════════════
    osintForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const value = osintInput.value.trim();
        if (!value) return;

        const config = TYPE_CONFIG[currentType];
        setLoading(true);

        try {
            const res = await fetch(config.endpoint, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ [config.field]: value }),
            });
            const data = await res.json();
            if (data.error) {
                alert('Analysis error: ' + data.error);
            } else {
                displayResults(data);
            }
        } catch (err) {
            alert('Analysis failed. Check server connection.');
        } finally {
            setLoading(false);
        }
    });

    function setLoading(loading) {
        osintBtn.querySelector('.btn-text').hidden = loading;
        osintBtn.querySelector('.btn-loader').hidden = !loading;
        osintBtn.disabled = loading;
    }

    // ═══════════════ RENDER RESULTS ═══════════════
    /**
     * Displays OSINT results on the dashboard
     */
    function displayResults(data) {
        if (!data || data.error) {
            showStatus('Error: ' + (data?.error || 'Analysis failed'), 'error');
            return;
        }

        // Show results area
        osintResults.hidden = false;

        // Update Gauge
        const score = data.riskScore || data.footprintScore || data.reputationScore || 0;
        const level = data.riskLevel || data.exposureLevel || 'unknown';

        $('#gauge-score').textContent = score;
        $('#gauge-level').textContent = level.toUpperCase();
        $('#gauge-level').style.color = getLevelColor(level);

        // Animate Gauge Progress
        const C = 2 * Math.PI * 50; // Circumference for a radius of 50
        const offset = C - (score / 100) * C;
        const gaugeProgress = $('#gauge-progress');
        gaugeProgress.style.strokeDasharray = C;
        gaugeProgress.style.strokeDashoffset = offset;
        gaugeProgress.style.stroke = getLevelColor(level);

        // Update Summary
        $('#gauge-summary').textContent = data.summary || `Analysis complete for ${data.query}`;

        // Update Quick Stats
        // renderQuickStats(data); // This function needs to be implemented or adapted

        // Render Findings
        renderFindings(data.findings);

        // Render Recommendations
        renderRecommendations(data.recommendations);

        // Render Detailed Table
        // renderDetailedTable(data); // This function needs to be implemented or adapted

        // Render Charts
        // renderCharts(data); // This function needs to be implemented or adapted

        // Update Tags
        // renderTags(data); // This function needs to be implemented or adapted

        // Scroll to results
        osintResults.scrollIntoView({ behavior: 'smooth', block: 'start' });

        // Call specific render functions based on data type
        switch (data.type) {
            case 'username': renderUsernameResults(data); break;
            case 'website': renderWebsiteResults(data); break;
            case 'email': renderEmailResults(data); break;
            case 'phone': renderPhoneResults(data); break;
            case 'domain': renderDomainResults(data); break;
        }
    }

    function getLevelColor(level) {
        switch (level.toLowerCase()) {
            case 'critical': return 'var(--red)';
            case 'high': return 'var(--magenta)';
            case 'medium': return 'var(--yellow)';
            case 'low': return 'var(--mint)'; // Assuming --mint is a defined CSS variable
            default: return 'var(--cyan)';
        }
    }

    function showStatus(message, type) {
        console.log(`Status (${type}): ${message}`);
        // Implement actual status display logic here (e.g., a toast notification)
        alert(message);
    }

    // ── Gauge ──
    function updateGauge(score, label, level, color, summary) {
        const C = 2 * Math.PI * 50;
        const offset = C - (score / 100) * C;
        const progressEl = $('#gauge-progress');
        if (progressEl) {
            progressEl.style.stroke = color;
            progressEl.style.strokeDasharray = C;
            progressEl.style.strokeDashoffset = offset;
        }

        const scoreEl = $('#gauge-score');
        if (scoreEl) {
            scoreEl.textContent = score;
            scoreEl.style.color = color;
        }

        const labelEl = $('#gauge-label');
        if (labelEl) labelEl.textContent = label;

        const levelEl = $('#gauge-level');
        if (levelEl) {
            levelEl.textContent = level.toUpperCase();
            levelEl.style.color = color;
        }

        const summaryEl = $('#gauge-summary');
        if (summaryEl) summaryEl.textContent = summary;
    }

    // ── Quick Stats ──
    function updateQuickStats(items) {
        const el = $('#osint-quick-stats');
        if (!el) return;
        el.innerHTML = items.map(item => `
            <div class="quick-stat">
                <span class="quick-stat-icon">${item.icon}</span>
                <div class="quick-stat-info">
                    <span class="quick-stat-value" style="color:${item.color || 'var(--cyan)'}">${item.value}</span>
                    <span class="quick-stat-label">${item.label}</span>
                </div>
            </div>
        `).join('');
    }

    // ── Findings ──
    function renderFindings(findings) {
        const el = $('#osint-findings');
        if (!el) return;
        if (!findings || !findings.length) {
            el.innerHTML = '<div class="no-data">No findings to report</div>';
            return;
        }
        el.innerHTML = findings.map(f => {
            const color = f.severity === 'critical' ? 'var(--magenta)' : f.severity === 'high' ? 'var(--red)' : f.severity === 'medium' ? 'var(--yellow)' : f.severity === 'info' ? 'var(--cyan)' : 'var(--green)';
            return `<div class="finding-item" style="border-left-color:${color}">
                <span class="finding-label">${f.label}</span>
                <span class="finding-detail">${f.detail}</span>
                <span class="finding-badge" style="color:${color};border-color:${color}">${f.severity.toUpperCase()}</span>
            </div>`;
        }).join('');
    }

    // ── Recommendations ──
    function renderRecommendations(recs) {
        const el = $('#osint-recommendations');
        if (!el) return;
        if (!recs || !recs.length) {
            el.innerHTML = '<div class="no-data">No recommendations available</div>';
            return;
        }
        el.innerHTML = recs.map(r =>
            `<div class="recommendation"><span class="rec-icon">⚡</span><span>${r}</span></div>`
        ).join('');
    }

    // ═══════════════ USERNAME RESULTS ═══════════════
    function renderUsernameResults(data) {
        updateGauge(data.footprintScore, 'FOOTPRINT', data.exposureLevel, data.exposureColor, data.summary);

        updateQuickStats([
            { icon: '🔍', value: data.totalPlatformsChecked, label: 'PLATFORMS CHECKED', color: 'var(--cyan)' },
            { icon: '✅', value: data.foundCount, label: 'PROFILES FOUND', color: 'var(--green)' },
            { icon: '📊', value: data.usernameAnalysis?.entropy || '—', label: 'ENTROPY', color: 'var(--purple)' },
            { icon: '⏱️', value: data.duration + 'ms', label: 'SCAN TIME', color: 'var(--yellow)' },
        ]);

        // Charts
        const chart1Title = $('#chart1-title');
        if (chart1Title) chart1Title.textContent = 'PLATFORM PRESENCE BY CATEGORY';
        const chart2Title = $('#chart2-title');
        if (chart2Title) chart2Title.textContent = 'CONFIDENCE DISTRIBUTION';

        const categories = data.categoryBreakdown || {};
        renderBarChart('chart-main', Object.keys(categories), Object.values(categories), 'Platforms Found');

        const found = data.platforms?.filter(p => p.found) || [];
        const confBuckets = { 'High (80-100)': 0, 'Medium (60-79)': 0, 'Low (<60)': 0 };
        found.forEach(p => {
            if (p.confidence >= 80) confBuckets['High (80-100)']++;
            else if (p.confidence >= 60) confBuckets['Medium (60-79)']++;
            else confBuckets['Low (<60)']++;
        });
        renderDoughnutChart('chart-secondary', Object.keys(confBuckets), Object.values(confBuckets));

        // Table
        const tableTitle = $('#table-title');
        if (tableTitle) tableTitle.textContent = `PLATFORM RESULTS (${data.platforms?.length || 0})`;
        renderPlatformTable(data.platforms || []);

        // Tags
        renderTags(found.map(p => ({ text: p.platform, color: p.riskLevel === 'high' ? 'var(--red)' : p.riskLevel === 'medium' ? 'var(--yellow)' : 'var(--green)' })));
    }

    // ═══════════════ WEBSITE RESULTS ═══════════════
    function renderWebsiteResults(data) {
        updateGauge(data.securityScore, 'SECURITY', data.riskLevel, data.riskColor, data.summary);

        const presentCount = data.securityHeaders?.present?.length || 0;
        const missingCount = data.securityHeaders?.missing?.length || 0;

        updateQuickStats([
            { icon: '🛡️', value: presentCount, label: 'HEADERS PRESENT', color: 'var(--green)' },
            { icon: '⚠️', value: missingCount, label: 'HEADERS MISSING', color: 'var(--red)' },
            { icon: '💻', value: data.techStack?.length || 0, label: 'TECHS DETECTED', color: 'var(--cyan)' },
            { icon: '⏱️', value: data.duration + 'ms', label: 'SCAN TIME', color: 'var(--yellow)' },
        ]);

        // Charts
        const chart1Title = $('#chart1-title');
        if (chart1Title) chart1Title.textContent = 'TECHNOLOGY STACK';
        const techs = data.techStack || [];
        renderBarChart('chart-main',
            techs.map(t => t.name),
            techs.map(t => t.confidence),
            'Confidence %'
        );

        const chart2Title = $('#chart2-title');
        if (chart2Title) chart2Title.textContent = 'SECURITY HEADERS';
        renderDoughnutChart('chart-secondary', ['Present', 'Missing'], [presentCount, missingCount]);

        // Table
        const tableTitle = $('#table-title');
        if (tableTitle) tableTitle.textContent = 'SECURITY HEADERS & TECH DETAILS';
        renderWebsiteTable(data);

        renderTags(techs.map(t => ({ text: `${t.icon} ${t.name}`, color: 'var(--cyan)' })));
    }

    // ═══════════════ EMAIL RESULTS ═══════════════
    function renderEmailResults(data) {
        updateGauge(data.riskScore, 'RISK', data.riskLevel, data.riskColor, data.summary);

        updateQuickStats([
            { icon: data.provider?.icon || '📧', value: data.provider?.name || '—', label: 'PROVIDER', color: 'var(--cyan)' },
            { icon: '🔓', value: data.breachCount, label: 'BREACHES', color: data.breachCount > 0 ? 'var(--red)' : 'var(--green)' },
            { icon: '📨', value: data.mxRecords?.length || 0, label: 'MX RECORDS', color: 'var(--purple)' },
            { icon: '✅', value: data.domainValid ? 'VALID' : 'INVALID', label: 'DOMAIN', color: data.domainValid ? 'var(--green)' : 'var(--red)' },
        ]);

        // Charts
        const chart1Title = $('#chart1-title');
        if (chart1Title) chart1Title.textContent = 'RISK BREAKDOWN';
        const riskFactors = [];
        const riskValues = [];
        if (data.formatAnalysis?.isDisposable) { riskFactors.push('Disposable'); riskValues.push(35); }
        if (data.breachCount > 0) { riskFactors.push('Breaches'); riskValues.push(data.breachCount * 6); }
        if (!data.domainValid) { riskFactors.push('Invalid MX'); riskValues.push(20); }
        if (data.provider?.risk === 'medium') { riskFactors.push('Provider Risk'); riskValues.push(10); }
        if (riskFactors.length === 0) { riskFactors.push('Clean'); riskValues.push(10); }
        renderBarChart('chart-main', riskFactors, riskValues, 'Risk Score');

        const chart2Title = $('#chart2-title');
        if (chart2Title) chart2Title.textContent = 'EMAIL CLASSIFICATION';
        renderDoughnutChart('chart-secondary', ['Provider Type', 'Format', 'Breach Exposure'], [
            data.provider?.type === 'encrypted' ? 40 : 20,
            data.formatAnalysis?.aliasDetected ? 30 : 15,
            Math.min(data.breachCount * 10, 40),
        ]);

        // Table
        const tableTitle = $('#table-title');
        if (tableTitle) tableTitle.textContent = 'EMAIL INTELLIGENCE DETAILS';
        renderEmailTable(data);

        const tags = [{ text: data.provider?.type?.toUpperCase() || 'UNKNOWN', color: 'var(--cyan)' }];
        if (data.formatAnalysis?.isDisposable) tags.push({ text: 'DISPOSABLE', color: 'var(--red)' });
        if (data.formatAnalysis?.aliasDetected) tags.push({ text: 'ALIAS', color: 'var(--yellow)' });
        if (data.breachCount > 0) tags.push({ text: `${data.breachCount} BREACHES`, color: 'var(--red)' });
        renderTags(tags);
    }

    // ═══════════════ PHONE RESULTS ═══════════════
    function renderPhoneResults(data) {
        updateGauge(data.riskScore, 'RISK', data.riskLevel, data.riskColor, data.summary);

        updateQuickStats([
            { icon: data.flag || '🌍', value: data.country, label: 'COUNTRY', color: 'var(--cyan)' },
            { icon: '📡', value: data.carrier, label: 'CARRIER', color: 'var(--purple)' },
            { icon: '📱', value: data.numberType?.toUpperCase(), label: 'TYPE', color: 'var(--green)' },
            { icon: '🔢', value: data.digitCount, label: 'DIGITS', color: 'var(--yellow)' },
        ]);

        // Charts
        const chart1Title = $('#chart1-title');
        if (chart1Title) chart1Title.textContent = 'RISK FACTORS';
        const factors = [];
        const scores = [];
        if (!data.isValidFormat) { factors.push('Invalid Format'); scores.push(30); }
        if (data.isVoIP) { factors.push('VoIP Number'); scores.push(20); }
        if (data.numberType === 'short_code') { factors.push('Short Code'); scores.push(20); }
        if (factors.length === 0) { factors.push('Low Risk'); scores.push(15); }
        renderBarChart('chart-main', factors, scores, 'Risk Score');

        const chart2Title = $('#chart2-title');
        if (chart2Title) chart2Title.textContent = 'NUMBER ANALYSIS';
        renderDoughnutChart('chart-secondary', ['Country Code', 'National Number', 'VoIP Risk'], [
            data.countryCode ? 30 : 10,
            data.nationalNumber?.length > 8 ? 40 : 20,
            data.isVoIP ? 30 : 5,
        ]);

        // Table
        const tableTitle = $('#table-title');
        if (tableTitle) tableTitle.textContent = 'PHONE INTELLIGENCE DETAILS';
        renderPhoneTable(data);

        const tags = [
            { text: data.country, color: 'var(--cyan)' },
            { text: data.numberType?.toUpperCase(), color: 'var(--green)' },
        ];
        if (data.isVoIP) tags.push({ text: 'VoIP', color: 'var(--red)' });
        renderTags(tags);
    }

    // ═══════════════ DOMAIN RESULTS ═══════════════
    function renderDomainResults(data) {
        updateGauge(data.reputationScore, 'REPUTATION', data.riskLevel, data.riskColor, data.summary);

        updateQuickStats([
            { icon: '🏢', value: data.whois?.registrar || '—', label: 'REGISTRAR', color: 'var(--cyan)' },
            { icon: '📅', value: data.whois?.domainAge + 'y', label: 'DOMAIN AGE', color: data.whois?.domainAge > 5 ? 'var(--green)' : 'var(--yellow)' },
            { icon: '🌐', value: data.subdomains?.length || 0, label: 'SUBDOMAINS', color: 'var(--purple)' },
            { icon: '📡', value: data.dns?.records?.A?.length || 0, label: 'DNS A RECORDS', color: 'var(--cyan)' },
        ]);

        // Charts
        const chart1Title = $('#chart1-title');
        if (chart1Title) chart1Title.textContent = 'DNS RECORD DISTRIBUTION';
        const records = data.dns?.records || {};
        const recTypes = Object.keys(records).filter(k => records[k].length > 0);
        const recCounts = recTypes.map(k => records[k].length);
        renderBarChart('chart-main', recTypes, recCounts, 'Record Count');

        const chart2Title = $('#chart2-title');
        if (chart2Title) chart2Title.textContent = 'DOMAIN HEALTH';
        renderDoughnutChart('chart-secondary', ['Reputation', 'DNS Health', 'Privacy'], [
            data.reputationScore,
            recTypes.length * 15,
            data.whois?.privacy ? 30 : 10,
        ]);

        // Table
        const tableTitle = $('#table-title');
        if (tableTitle) tableTitle.textContent = 'DOMAIN INTELLIGENCE DETAILS';
        renderDomainTable(data);

        const tags = [
            { text: `.${data.tld}`.toUpperCase(), color: 'var(--cyan)' },
            { text: data.whois?.registrar, color: 'var(--purple)' },
        ];
        if (data.whois?.privacy) tags.push({ text: 'WHOIS PRIVACY', color: 'var(--green)' });
        data.subdomains?.slice(0, 4).forEach(s => tags.push({ text: s.name, color: 'var(--yellow)' }));
        renderTags(tags);
    }

    // ═══════════════ CHART RENDERING ═══════════════
    const chartColors = {
        bar: ['#00f0ff', '#ff006e', '#00ff88', '#ffaa00', '#8080ff', '#ff4444', '#00ccaa', '#ff8800'],
        doughnut: ['#00f0ff', '#ff006e', '#00ff88', '#ffaa00', '#8080ff', '#ff4444'],
    };

    function getChartDefaults() {
        const isDark = document.documentElement.getAttribute('data-theme') !== 'light';
        return {
            textColor: isDark ? '#8888aa' : '#555580',
            gridColor: isDark ? 'rgba(255,255,255,0.05)' : 'rgba(0,0,0,0.05)',
        };
    }

    function renderBarChart(canvasId, labels, values, label) {
        const canvas = document.getElementById(canvasId);
        if (!canvas) return;
        const ctx = canvas.getContext('2d');
        const defaults = getChartDefaults();

        if (canvasId === 'chart-main' && chartMain) chartMain.destroy();
        if (canvasId === 'chart-secondary' && chartSecondary) chartSecondary.destroy();

        const chart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels,
                datasets: [{
                    label,
                    data: values,
                    backgroundColor: labels.map((_, i) => chartColors.bar[i % chartColors.bar.length] + '44'),
                    borderColor: labels.map((_, i) => chartColors.bar[i % chartColors.bar.length]),
                    borderWidth: 1,
                    borderRadius: 6,
                }],
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { labels: { color: defaults.textColor, font: { family: "'JetBrains Mono'" } } },
                },
                scales: {
                    x: {
                        ticks: { color: defaults.textColor, font: { family: "'JetBrains Mono'", size: 10 }, maxRotation: 45 },
                        grid: { color: defaults.gridColor },
                    },
                    y: {
                        ticks: { color: defaults.textColor, font: { family: "'JetBrains Mono'", size: 10 } },
                        grid: { color: defaults.gridColor },
                    },
                },
            },
        });

        if (canvasId === 'chart-main') chartMain = chart;
        else chartSecondary = chart;
    }

    function renderDoughnutChart(canvasId, labels, values) {
        const canvas = document.getElementById(canvasId);
        if (!canvas) return;
        const ctx = canvas.getContext('2d');
        const defaults = getChartDefaults();

        if (canvasId === 'chart-main' && chartMain) chartMain.destroy();
        if (canvasId === 'chart-secondary' && chartSecondary) chartSecondary.destroy();

        const chart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels,
                datasets: [{
                    data: values,
                    backgroundColor: labels.map((_, i) => chartColors.doughnut[i % chartColors.doughnut.length] + '66'),
                    borderColor: labels.map((_, i) => chartColors.doughnut[i % chartColors.doughnut.length]),
                    borderWidth: 2,
                }],
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: '55%',
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: { color: defaults.textColor, font: { family: "'JetBrains Mono'", size: 11 }, padding: 16 },
                    },
                },
            },
        });

        if (canvasId === 'chart-main') chartMain = chart;
        else chartSecondary = chart;
    }

    // ═══════════════ TABLE RENDERING ═══════════════
    function renderPlatformTable(platforms) {
        const container = $('#osint-table-content');
        if (!container) return;
        const rows = platforms.map(p => `
            <tr class="${p.found ? 'found' : 'not-found'}">
                <td>${p.icon} ${p.platform}</td>
                <td>${p.category}</td>
                <td><span class="status-dot-inline ${p.found ? 'active' : ''}"></span> ${p.found ? 'Found' : 'Not Found'}</td>
                <td>${p.found ? p.confidence + '%' : '—'}</td>
                <td>${p.found ? `<a href="${p.url}" target="_blank" class="table-link">View ↗</a>` : '—'}</td>
            </tr>
        `).join('');

        container.innerHTML = `<table class="osint-table">
            <thead><tr><th>PLATFORM</th><th>CATEGORY</th><th>STATUS</th><th>CONFIDENCE</th><th>LINK</th></tr></thead>
            <tbody>${rows}</tbody>
        </table>`;
    }

    function renderWebsiteTable(data) {
        const container = $('#osint-table-content');
        if (!container) return;
        let rows = '';

        // Security headers
        (data.securityHeaders?.present || []).forEach(h => {
            rows += `<tr><td>🟢 ${h.name}</td><td>Security Header</td><td>Present</td><td>${truncate(h.value, 50)}</td><td><span class="finding-badge" style="color:var(--green);border-color:var(--green)">PASS</span></td></tr>`;
        });
        (data.securityHeaders?.missing || []).forEach(h => {
            rows += `<tr><td>🔴 ${h.name}</td><td>Security Header</td><td>Missing</td><td>${h.description}</td><td><span class="finding-badge" style="color:var(--red);border-color:var(--red)">${h.severity.toUpperCase()}</span></td></tr>`;
        });

        // Tech stack
        (data.techStack || []).forEach(t => {
            rows += `<tr><td>${t.icon} ${t.name}</td><td>${t.category}</td><td>Detected</td><td>Confidence: ${t.confidence}%</td><td><span class="finding-badge" style="color:var(--cyan);border-color:var(--cyan)">TECH</span></td></tr>`;
        });

        container.innerHTML = `<table class="osint-table">
            <thead><tr><th>ITEM</th><th>CATEGORY</th><th>STATUS</th><th>DETAILS</th><th>LEVEL</th></tr></thead>
            <tbody>${rows}</tbody>
        </table>`;
    }

    function renderEmailTable(data) {
        const container = $('#osint-table-content');
        if (!container) return;
        let rows = '';

        rows += `<tr><td>📧 Local Part</td><td>${data.formatAnalysis?.localPart}</td><td>Length: ${data.formatAnalysis?.localPartLength}</td></tr>`;
        rows += `<tr><td>🌐 Domain</td><td>${data.formatAnalysis?.domain}</td><td>${data.domainValid ? '✅ Valid MX' : '❌ No MX'}</td></tr>`;
        rows += `<tr><td>${data.provider?.icon} Provider</td><td>${data.provider?.name}</td><td>Type: ${data.provider?.type}</td></tr>`;

        (data.mxRecords || []).forEach(mx => {
            rows += `<tr><td>📨 MX Record</td><td>${mx.exchange}</td><td>Priority: ${mx.priority}</td></tr>`;
        });

        (data.breaches || []).forEach(b => {
            rows += `<tr><td>🔓 Breach</td><td>${b.source}</td><td>Date: ${b.date} (${b.dataTypes.join(', ')})</td></tr>`;
        });

        container.innerHTML = `<table class="osint-table">
            <thead><tr><th>FIELD</th><th>VALUE</th><th>DETAILS</th></tr></thead>
            <tbody>${rows}</tbody>
        </table>`;
    }

    function renderPhoneTable(data) {
        const container = $('#osint-table-content');
        if (!container) return;
        let rows = '';

        rows += `<tr><td>📱 Formatted</td><td>${data.formatted}</td><td>—</td></tr>`;
        rows += `<tr><td>${data.flag} Country</td><td>${data.country}</td><td>Code: +${data.countryCode || '?'}</td></tr>`;
        rows += `<tr><td>📡 Carrier</td><td>${data.carrier}</td><td>—</td></tr>`;
        rows += `<tr><td>📞 Type</td><td>${data.numberType}</td><td>${data.digitCount} digits</td></tr>`;
        rows += `<tr><td>🌐 VoIP</td><td>${data.isVoIP ? '⚠ Yes' : '✅ No'}</td><td>${data.isVoIP ? 'Virtual number detected' : 'Standard carrier'}</td></tr>`;
        rows += `<tr><td>✅ Valid Format</td><td>${data.isValidFormat ? 'Yes' : 'No'}</td><td>—</td></tr>`;

        container.innerHTML = `<table class="osint-table">
            <thead><tr><th>FIELD</th><th>VALUE</th><th>DETAILS</th></tr></thead>
            <tbody>${rows}</tbody>
        </table>`;
    }

    function renderDomainTable(data) {
        const container = $('#osint-table-content');
        if (!container) return;
        let rows = '';

        rows += `<tr><td>🏢 Registrar</td><td>${data.whois?.registrar || '—'}</td><td>—</td></tr>`;
        rows += `<tr><td>📅 Created</td><td>${data.whois?.created || '—'}</td><td>Age: ${data.whois?.domainAge}y</td></tr>`;
        rows += `<tr><td>📅 Expires</td><td>${data.whois?.expires || '—'}</td><td>Status: ${data.whois?.status}</td></tr>`;
        rows += `<tr><td>🔒 Privacy</td><td>${data.whois?.privacy ? 'Enabled' : 'Disabled'}</td><td>—</td></tr>`;

        const records = data.dns?.records || {};
        Object.entries(records).forEach(([type, vals]) => {
            vals.forEach(v => {
                rows += `<tr><td>📡 ${type} Record</td><td>${truncate(v, 60)}</td><td>DNS</td></tr>`;
            });
        });

        (data.subdomains || []).forEach(s => {
            rows += `<tr><td>🌐 Subdomain</td><td>${s.name}</td><td>Type: ${s.type}</td></tr>`;
        });

        container.innerHTML = `<table class="osint-table">
            <thead><tr><th>FIELD</th><th>VALUE</th><th>DETAILS</th></tr></thead>
            <tbody>${rows}</tbody>
        </table>`;
    }

    // ── Tags ──
    function renderTags(tags) {
        const el = $('#osint-tags');
        if (!el) return;
        if (!tags) return;
        el.innerHTML = tags.map(t =>
            `<span class="osint-tag" style="color:${t.color};border-color:${t.color}">${t.text}</span>`
        ).join('');
    }

    // ── Helpers ──
    function truncate(str, len) {
        if (!str) return '—';
        return str.length > len ? str.substring(0, len) + '...' : str;
    }

})();
