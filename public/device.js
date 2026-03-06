(function () {
    'use strict';
    const $ = (sel) => document.querySelector(sel);

    // Clock
    const liveClock = $('#live-clock');
    setInterval(() => { liveClock.textContent = new Date().toTimeString().split(' ')[0]; }, 1000);
    liveClock.textContent = new Date().toTimeString().split(' ')[0];

    // Particles
    (() => {
        const c = $('#particles');
        if (!c) return;
        for (let i = 0; i < 40; i++) {
            const p = document.createElement('div');
            p.className = 'particle';
            p.style.left = Math.random() * 100 + '%';
            p.style.animationDuration = (8 + Math.random() * 12) + 's';
            p.style.animationDelay = (Math.random() * 10) + 's';
            const s = (1 + Math.random() * 2) + 'px';
            p.style.width = s; p.style.height = s;
            c.appendChild(p);
        }
    })();

    const scanBtn = $('#scan-start-btn');
    const scanProgress = $('#scan-progress');
    const progressFill = $('#progress-fill');
    const progressText = $('#progress-text');
    const resultsSection = $('#device-results');

    scanBtn.addEventListener('click', startScan);

    async function startScan() {
        scanBtn.querySelector('.btn-text').hidden = true;
        scanBtn.querySelector('.btn-loader').hidden = false;
        scanProgress.hidden = false;
        resultsSection.hidden = true;

        const steps = [
            { text: 'Checking browser fingerprint...', pct: 15 },
            { text: 'Testing WebRTC leak...', pct: 30 },
            { text: 'Analyzing cookies & storage...', pct: 45 },
            { text: 'Detecting plugins & features...', pct: 60 },
            { text: 'Checking canvas fingerprint...', pct: 75 },
            { text: 'Sending to analysis engine...', pct: 90 },
        ];

        for (const step of steps) {
            progressText.textContent = step.text;
            progressFill.style.width = step.pct + '%';
            await delay(400 + Math.random() * 300);
        }

        // Collect all client-side data
        const clientData = {
            userAgent: navigator.userAgent,
            platform: navigator.platform || navigator.userAgentData?.platform || 'Unknown',
            language: navigator.language,
            languages: navigator.languages ? [...navigator.languages] : [],
            screen: screen.width + 'x' + screen.height,
            colorDepth: screen.colorDepth,
            timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
            hardwareConcurrency: navigator.hardwareConcurrency || 'Unknown',
            deviceMemory: navigator.deviceMemory || 'Unknown',
            touchSupport: 'ontouchstart' in window,
            cookiesEnabled: navigator.cookieEnabled,
            doNotTrack: navigator.doNotTrack,
            thirdPartyCookies: false,
            pluginCount: navigator.plugins ? navigator.plugins.length : 0,
            canvasHash: getCanvasFingerprint(),
            webglRenderer: getWebGLRenderer(),
            webrtcIPs: [],
            protocol: window.location.protocol,
        };

        // WebRTC leak test
        try {
            const ips = await getWebRTCIPs();
            clientData.webrtcIPs = ips;
        } catch { /* ignore */ }

        progressText.textContent = 'Analyzing results...';
        progressFill.style.width = '95%';

        // Send to server
        try {
            const res = await fetch('/api/device/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(clientData),
            });
            const result = await res.json();
            progressFill.style.width = '100%';
            await delay(300);
            renderResults(result);
        } catch (err) {
            alert('Scan failed: ' + err.message);
        }

        scanBtn.querySelector('.btn-text').hidden = false;
        scanBtn.querySelector('.btn-loader').hidden = true;
        scanBtn.querySelector('.btn-text').textContent = '🔄 RE-SCAN';
    }

    function renderResults(data) {
        resultsSection.hidden = false;
        scanProgress.hidden = true;

        // Score ring animation
        const scoreVal = $('#score-value');
        const ring = $('#score-ring-circle');
        const grade = $('#score-grade');
        const desc = $('#score-desc');

        const circumference = 327;
        const offset = circumference - (data.score / 100) * circumference;
        ring.style.strokeDashoffset = offset;

        let color;
        if (data.score >= 80) color = 'var(--green)';
        else if (data.score >= 60) color = '#ffcc00';
        else if (data.score >= 40) color = '#ff9900';
        else color = '#ff3366';
        ring.style.stroke = color;
        scoreVal.style.color = color;
        grade.style.color = color;

        animateNumber(scoreVal, data.score);
        grade.textContent = data.grade;

        if (data.score >= 80) desc.textContent = 'Your device has good security posture';
        else if (data.score >= 60) desc.textContent = 'Some privacy concerns detected';
        else if (data.score >= 40) desc.textContent = 'Multiple vulnerabilities found';
        else desc.textContent = 'Critical security issues — take action immediately';

        // Findings
        const findingsGrid = $('#findings-grid');
        findingsGrid.innerHTML = data.findings.map((f) => `
      <div class="finding-card ${f.severity}">
        <div class="finding-header">
          <span class="finding-category">${f.category}</span>
        </div>
        <div class="finding-title">${f.title}</div>
        <div class="finding-desc">${f.description}</div>
      </div>
    `).join('');

        // Device info
        const infoGrid = $('#device-info-grid');
        const info = data.deviceInfo || {};
        const infoItems = [
            { label: 'Platform', value: info.platform },
            { label: 'Language', value: info.language },
            { label: 'Screen', value: info.screen },
            { label: 'Color Depth', value: info.colorDepth + ' bit' },
            { label: 'Timezone', value: info.timezone },
            { label: 'CPU Cores', value: info.hardwareConcurrency },
            { label: 'Memory', value: info.deviceMemory ? info.deviceMemory + ' GB' : 'Hidden' },
            { label: 'Touch', value: info.touchSupport ? 'Yes' : 'No' },
        ];
        infoGrid.innerHTML = infoItems.map((i) => `
      <div class="info-item">
        <div class="info-label">${i.label}</div>
        <div class="info-value">${i.value || 'Unknown'}</div>
      </div>
    `).join('');
    }

    // Security Headers Check
    const headerForm = $('#header-check-form');
    const headerUrlInput = $('#header-url-input');
    const headerBtn = $('#header-check-btn');
    const headersResults = $('#headers-results');

    headerForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const url = headerUrlInput.value.trim();
        if (!url) return;

        headerBtn.querySelector('.btn-text').hidden = true;
        headerBtn.querySelector('.btn-loader').hidden = false;

        try {
            const res = await fetch('/api/device/headers', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url }),
            });
            const data = await res.json();
            renderHeaders(data);
        } catch { headersResults.innerHTML = '<p style="color:#ff3366">Failed to check headers</p>'; }

        headerBtn.querySelector('.btn-text').hidden = false;
        headerBtn.querySelector('.btn-loader').hidden = true;
    });

    function renderHeaders(data) {
        if (data.error) {
            headersResults.innerHTML = `<p style="color:#ff3366">${data.error}</p>`;
            return;
        }

        let gradeColor;
        if (data.grade.startsWith('A')) gradeColor = 'var(--green)';
        else if (data.grade === 'B') gradeColor = 'var(--cyan)';
        else if (data.grade === 'C') gradeColor = '#ffcc00';
        else gradeColor = '#ff3366';

        headersResults.innerHTML = `
      <div class="header-grade">
        <div class="header-grade-letter" style="color:${gradeColor}">${data.grade}</div>
        <div class="header-grade-score">${data.passed}/${data.total} headers present (${data.score}%)</div>
      </div>
      ${data.checks.map((c) => `
        <div class="header-row">
          <span class="header-status">${c.present ? '✅' : '❌'}</span>
          <span class="header-name">${c.name}</span>
          <span class="header-desc">${c.description}</span>
        </div>
      `).join('')}
    `;
    }

    // Helpers
    function getCanvasFingerprint() {
        try {
            const canvas = document.createElement('canvas');
            const ctx = canvas.getContext('2d');
            ctx.textBaseline = 'top';
            ctx.font = '14px Arial';
            ctx.fillText('CHECK-IT fingerprint test 🔐', 2, 2);
            ctx.fillStyle = 'rgba(0,255,255,0.5)';
            ctx.fillRect(50, 10, 30, 20);
            const data = canvas.toDataURL();
            let hash = 0;
            for (let i = 0; i < data.length; i++) {
                hash = ((hash << 5) - hash) + data.charCodeAt(i);
                hash |= 0;
            }
            return Math.abs(hash).toString(16);
        } catch { return null; }
    }

    function getWebGLRenderer() {
        try {
            const canvas = document.createElement('canvas');
            const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
            if (!gl) return 'Not supported';
            const ext = gl.getExtension('WEBGL_debug_renderer_info');
            if (ext) return gl.getParameter(ext.UNMASKED_RENDERER_WEBGL);
            return 'Hidden';
        } catch { return 'Unknown'; }
    }

    function getWebRTCIPs() {
        return new Promise((resolve) => {
            const ips = [];
            try {
                const pc = new RTCPeerConnection({ iceServers: [{ urls: 'stun:stun.l.google.com:19302' }] });
                pc.createDataChannel('');
                pc.createOffer().then((o) => pc.setLocalDescription(o)).catch(() => { });
                pc.onicecandidate = (e) => {
                    if (!e.candidate) { pc.close(); resolve(ips); return; }
                    const match = e.candidate.candidate.match(/(\d+\.\d+\.\d+\.\d+)/);
                    if (match && !ips.includes(match[1])) ips.push(match[1]);
                };
                setTimeout(() => { pc.close(); resolve(ips); }, 3000);
            } catch { resolve(ips); }
        });
    }

    function animateNumber(el, target) {
        let current = 0;
        const step = Math.max(1, Math.floor(target / 30));
        const timer = setInterval(() => {
            current += step;
            if (current >= target) { current = target; clearInterval(timer); }
            el.textContent = current;
        }, 30);
    }

    function delay(ms) { return new Promise((r) => setTimeout(r, ms)); }
})();
