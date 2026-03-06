(function () {
    'use strict';
    const $ = (sel) => document.querySelector(sel);
    const $$ = (sel) => document.querySelectorAll(sel);

    // Clock
    setInterval(() => { $('#live-clock').textContent = new Date().toTimeString().split(' ')[0]; }, 1000);
    $('#live-clock').textContent = new Date().toTimeString().split(' ')[0];

    // Particles
    (() => { const c = $('#particles'); if (!c) return; for (let i = 0; i < 40; i++) { const p = document.createElement('div'); p.className = 'particle'; p.style.left = Math.random() * 100 + '%'; p.style.animationDuration = (8 + Math.random() * 12) + 's'; p.style.animationDelay = (Math.random() * 10) + 's'; const s = (1 + Math.random() * 2) + 'px'; p.style.width = s; p.style.height = s; c.appendChild(p); } })();

    // Tabs
    $$('.net-tab').forEach((tab) => {
        tab.addEventListener('click', () => {
            $$('.net-tab').forEach((t) => t.classList.remove('active'));
            $$('.net-panel').forEach((p) => (p.hidden = true));
            tab.classList.add('active');
            $(`#tab-${tab.dataset.tab}`).hidden = false;
        });
    });

    function setLoading(btn, loading) {
        btn.querySelector('.btn-text').hidden = loading;
        btn.querySelector('.btn-loader').hidden = !loading;
    }

    // === DNS LEAK TEST ===
    const dnsForm = $('#dns-form');
    const dnsBtn = $('#dns-btn');
    dnsForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const domain = $('#dns-domain').value.trim() || 'example.com';
        setLoading(dnsBtn, true);
        try {
            const res = await fetch('/api/network/dns-leak', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ domain }),
            });
            const data = await res.json();
            renderDNS(data);
        } catch { $('#dns-results').innerHTML = '<p style="color:#ff3366">Test failed</p>'; }
        setLoading(dnsBtn, false);
    });

    function renderDNS(data) {
        const el = $('#dns-results');
        el.innerHTML = `
      <div class="dns-resolvers">
        ${data.resolvers.map((r) => `
          <div class="dns-resolver-card">
            <span class="dns-status">${r.status === 'ok' ? '✅' : '❌'}</span>
            <span class="dns-resolver-name">${r.resolver}</span>
            <span class="dns-resolver-ips">${r.ips.length ? r.ips.join(', ') : 'No results'}</span>
          </div>
        `).join('')}
      </div>
      <div class="dns-verdict ${data.potentialLeak ? 'leak' : 'safe'}">
        ${data.potentialLeak ? '⚠️ POTENTIAL DNS LEAK DETECTED' : '✅ NO DNS LEAK DETECTED'}<br/>
        <small>${data.leakDescription}</small>
      </div>
    `;
    }

    // === PORT SCANNER ===
    const portForm = $('#port-form');
    const portBtn = $('#port-btn');
    portForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const target = $('#port-target').value.trim() || 'localhost';
        setLoading(portBtn, true);
        try {
            const res = await fetch('/api/network/port-scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target }),
            });
            const data = await res.json();
            renderPorts(data);
        } catch { $('#port-results').innerHTML = '<p style="color:#ff3366">Scan failed</p>'; }
        setLoading(portBtn, false);
    });

    function renderPorts(data) {
        const el = $('#port-results');
        const s = data.summary;
        let riskColor = s.riskLevel === 'critical' ? '#ff3366' : s.riskLevel === 'high' ? '#ff6633' : s.riskLevel === 'medium' ? '#ffcc00' : 'var(--green)';
        el.innerHTML = `
      <div class="port-summary">
        <div class="port-stat"><div class="port-stat-value" style="color:#ff3366">${s.open}</div><div class="port-stat-label">OPEN</div></div>
        <div class="port-stat"><div class="port-stat-value" style="color:#ffcc00">${s.filtered}</div><div class="port-stat-label">FILTERED</div></div>
        <div class="port-stat"><div class="port-stat-value" style="color:var(--green)">${s.closed}</div><div class="port-stat-label">CLOSED</div></div>
        <div class="port-stat"><div class="port-stat-value" style="color:${riskColor}">${s.riskLevel.toUpperCase()}</div><div class="port-stat-label">RISK</div></div>
      </div>
      <div class="port-grid">
        ${data.results.sort((a, b) => { const order = { open: 0, filtered: 1, closed: 2 }; return order[a.status] - order[b.status]; }).map((p) => `
          <div class="port-card ${p.status}">
            <span class="port-number">${p.port}</span>
            <span class="port-service">${p.service}</span>
            <span class="port-status-tag">${p.status.toUpperCase()}</span>
          </div>
        `).join('')}
      </div>
    `;
    }

    // === SSL CHECK ===
    const sslForm = $('#ssl-form');
    const sslBtn = $('#ssl-btn');
    sslForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const hostname = $('#ssl-hostname').value.trim();
        if (!hostname) return;
        setLoading(sslBtn, true);
        try {
            const res = await fetch('/api/network/ssl-check', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ hostname }),
            });
            const data = await res.json();
            renderSSL(data);
        } catch { $('#ssl-results').innerHTML = '<p style="color:#ff3366">SSL check failed</p>'; }
        setLoading(sslBtn, false);
    });

    function renderSSL(data) {
        const el = $('#ssl-results');
        if (data.error) {
            el.innerHTML = `<p style="color:#ff3366">${data.error}</p>`;
            return;
        }
        const cert = data.certificate;
        let gradeColor = data.grade === 'A' ? 'var(--green)' : data.grade === 'B' ? 'var(--cyan)' : data.grade === 'C' ? '#ffcc00' : '#ff3366';
        el.innerHTML = `
      <div class="ssl-grade-display">
        <div class="ssl-grade-letter" style="color:${gradeColor}">${data.grade}</div>
      </div>
      <div class="ssl-details">
        <div class="ssl-detail"><div class="ssl-detail-label">PROTOCOL</div><div class="ssl-detail-value">${data.protocol}</div></div>
        <div class="ssl-detail"><div class="ssl-detail-label">CIPHER</div><div class="ssl-detail-value">${data.cipher ? data.cipher.name : 'Unknown'}</div></div>
        <div class="ssl-detail"><div class="ssl-detail-label">ISSUER</div><div class="ssl-detail-value">${cert.issuer?.O || cert.issuer?.CN || 'Unknown'}</div></div>
        <div class="ssl-detail"><div class="ssl-detail-label">VALID FROM</div><div class="ssl-detail-value">${new Date(cert.validFrom).toLocaleDateString()}</div></div>
        <div class="ssl-detail"><div class="ssl-detail-label">EXPIRES</div><div class="ssl-detail-value">${new Date(cert.validTo).toLocaleDateString()} (${cert.daysRemaining} days)</div></div>
        <div class="ssl-detail"><div class="ssl-detail-label">SUBJECT</div><div class="ssl-detail-value">${cert.subject?.CN || data.hostname}</div></div>
        <div class="ssl-detail"><div class="ssl-detail-label">SERIAL</div><div class="ssl-detail-value">${cert.serialNumber || 'N/A'}</div></div>
        <div class="ssl-detail"><div class="ssl-detail-label">TRUSTED</div><div class="ssl-detail-value">${data.authorized ? '✅ Yes' : '⚠️ No'}</div></div>
      </div>
      ${data.findings.length ? '<div class="ssl-findings">' + data.findings.map((f) => `<div class="ssl-finding ${f.severity}">⚠️ ${f.message}</div>`).join('') + '</div>' : ''}
    `;
    }

    // === LATENCY TEST ===
    let latencyMap = null;
    const latencyBtn = $('#latency-btn');
    latencyBtn.addEventListener('click', async () => {
        setLoading(latencyBtn, true);
        try {
            const res = await fetch('/api/network/latency');
            const data = await res.json();
            renderLatency(data);
        } catch { $('#latency-results').innerHTML = '<p style="color:#ff3366">Latency test failed</p>'; }
        setLoading(latencyBtn, false);
    });

    function renderLatency(data) {
        // Map
        if (!latencyMap) {
            latencyMap = L.map('latency-map-container', {
                center: [20, 0], zoom: 2, attributionControl: false,
            });
            L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', { maxZoom: 18 }).addTo(latencyMap);
        }

        const maxLatency = Math.max(...data.results.filter((r) => r.latency).map((r) => r.latency), 1);

        data.results.forEach((r) => {
            if (!r.lat || !r.lng) return;
            const color = r.latency == null ? '#666' : r.latency < 200 ? '#00ff88' : r.latency < 500 ? '#ffcc00' : '#ff3366';
            const icon = L.divIcon({
                className: 'latency-marker',
                html: `<div style="width:12px;height:12px;border-radius:50%;background:${color};box-shadow:0 0 8px ${color}"></div>`,
                iconSize: [12, 12], iconAnchor: [6, 6],
            });
            L.marker([r.lat, r.lng], { icon }).addTo(latencyMap)
                .bindPopup(`<b>${r.name}</b><br/>${r.region}<br/>${r.latency != null ? r.latency + 'ms' : 'Timeout'}`);
        });

        // Results
        const el = $('#latency-results');
        el.innerHTML = `
      <div style="margin:12px 0;font-family:var(--font-mono);font-size:0.8rem;color:var(--text-dim)">
        Average: <strong style="color:var(--cyan)">${data.average || '—'}ms</strong> |
        Fastest: <strong style="color:var(--green)">${data.fastest ? data.fastest.name + ' (' + data.fastest.latency + 'ms)' : '—'}</strong>
      </div>
      <div class="latency-grid">
        ${data.results.map((r) => {
            const pct = r.latency != null ? Math.min(100, (r.latency / maxLatency) * 100) : 0;
            const color = r.latency == null ? '#666' : r.latency < 200 ? '#00ff88' : r.latency < 500 ? '#ffcc00' : '#ff3366';
            return `
            <div class="latency-row">
              <span class="latency-name">${r.name}</span>
              <span class="latency-region">${r.region}</span>
              <div class="latency-bar-container">
                <div class="latency-bar-fill" style="width:${pct}%;background:${color}"></div>
              </div>
              <span class="latency-value" style="color:${color}">${r.latency != null ? r.latency + 'ms' : 'Timeout'}</span>
            </div>
          `;
        }).join('')}
      </div>
    `;
    }
})();
