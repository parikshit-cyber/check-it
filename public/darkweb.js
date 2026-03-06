(function () {
    'use strict';
    const $ = (sel) => document.querySelector(sel);

    // Clock
    setInterval(() => { $('#live-clock').textContent = new Date().toTimeString().split(' ')[0]; }, 1000);
    $('#live-clock').textContent = new Date().toTimeString().split(' ')[0];

    // Particles
    (() => { const c = $('#particles'); if (!c) return; for (let i = 0; i < 40; i++) { const p = document.createElement('div'); p.className = 'particle'; p.style.left = Math.random() * 100 + '%'; p.style.animationDuration = (8 + Math.random() * 12) + 's'; p.style.animationDelay = (Math.random() * 10) + 's'; const s = (1 + Math.random() * 2) + 'px'; p.style.width = s; p.style.height = s; c.appendChild(p); } })();

    const form = $('#dw-form');
    const emailInput = $('#dw-email');
    const btn = $('#dw-btn');
    const scanning = $('#dw-scanning');
    const scanText = $('#scan-text');
    const resultsSection = $('#dw-results');

    const scanMessages = [
        'Scanning dark web databases...',
        'Searching breach records...',
        'Checking credential dumps...',
        'Analyzing data exposure...',
        'Correlating findings...',
        'Generating risk report...',
    ];

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        const email = emailInput.value.trim();
        if (!email) return;

        btn.querySelector('.btn-text').hidden = true;
        btn.querySelector('.btn-loader').hidden = false;
        scanning.hidden = false;
        resultsSection.hidden = true;

        // Animate scan messages
        let msgIdx = 0;
        const msgInterval = setInterval(() => {
            msgIdx = (msgIdx + 1) % scanMessages.length;
            scanText.textContent = scanMessages[msgIdx];
        }, 800);

        try {
            const res = await fetch('/api/darkweb/check', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email }),
            });
            const data = await res.json();
            clearInterval(msgInterval);
            scanning.hidden = true;
            renderResults(data);
        } catch (err) {
            clearInterval(msgInterval);
            scanning.hidden = true;
            alert('Scan failed: ' + err.message);
        }

        btn.querySelector('.btn-text').hidden = false;
        btn.querySelector('.btn-loader').hidden = true;
    });

    function renderResults(data) {
        resultsSection.hidden = false;

        // Risk score
        const riskNum = $('#dw-risk-number');
        const riskLevel = $('#dw-risk-level');
        const riskBreaches = $('#dw-risk-breaches');

        let riskColor;
        if (data.riskLevel === 'critical') riskColor = '#ff3366';
        else if (data.riskLevel === 'high') riskColor = '#ff6633';
        else if (data.riskLevel === 'medium') riskColor = '#ffcc00';
        else riskColor = 'var(--green)';

        riskNum.style.color = riskColor;
        riskLevel.style.color = riskColor;
        animateNumber(riskNum, data.riskScore);
        riskLevel.textContent = data.riskLevel + ' RISK';
        riskBreaches.textContent = `Found in ${data.breachCount} breaches | ${formatNumber(data.totalExposedRecords)} records exposed`;

        // Exposed data types
        const typesEl = $('#dw-exposed-types');
        const criticalTypes = ['password', 'ssn', 'payment', 'passport', 'drivers_license'];
        const highTypes = ['phone', 'address', 'birthdate', 'email'];
        typesEl.innerHTML = data.exposedDataTypes.map((t) => {
            let cls = 'low';
            if (criticalTypes.includes(t)) cls = 'critical';
            else if (highTypes.includes(t)) cls = 'high';
            else if (t === 'name' || t === 'username') cls = 'medium';
            return `<span class="dw-data-tag ${cls}">${t.replace('_', ' ')}</span>`;
        }).join('');

        // Breach timeline
        const timeline = $('#dw-timeline');
        timeline.innerHTML = data.breaches.map((b) => `
      <div class="breach-card ${b.severity}">
        <div class="breach-date">${new Date(b.date).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' })}</div>
        <div class="breach-info">
          <div class="breach-name">${b.name}</div>
          <div class="breach-desc">${b.description}</div>
          <div class="breach-data">
            ${b.dataTypes.map((d) => `<span class="breach-data-type">${d}</span>`).join('')}
          </div>
        </div>
        <div class="breach-records">${formatNumber(b.records)}</div>
      </div>
    `).join('');

        // Recommendations
        const recs = $('#dw-recs');
        recs.innerHTML = data.recommendations.map((r) => `
      <div class="rec-card">
        <span class="rec-priority ${r.priority}">${r.priority}</span>
        <div class="rec-content">
          <div class="rec-action">${r.action}</div>
          <div class="rec-detail">${r.detail}</div>
        </div>
      </div>
    `).join('');

        // Smooth scroll to results
        resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }

    function animateNumber(el, target) {
        let current = 0;
        const step = Math.max(1, Math.floor(target / 25));
        const timer = setInterval(() => {
            current += step;
            if (current >= target) { current = target; clearInterval(timer); }
            el.textContent = current;
        }, 30);
    }

    function formatNumber(n) {
        if (n >= 1e9) return (n / 1e9).toFixed(1) + 'B';
        if (n >= 1e6) return (n / 1e6).toFixed(1) + 'M';
        if (n >= 1e3) return (n / 1e3).toFixed(0) + 'K';
        return n.toString();
    }
})();
