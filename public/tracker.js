(function () {
    'use strict';
    const $ = (sel) => document.querySelector(sel);
    const $$ = (sel) => document.querySelectorAll(sel);

    // Clock
    const liveClock = $('#live-clock');
    function updateClock() {
        const now = new Date();
        liveClock.textContent = now.toTimeString().split(' ')[0];
    }
    setInterval(updateClock, 1000);
    updateClock();

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

    // State
    let activeLinkId = null;
    let trackerMap = null;
    let mapMarkers = [];
    let sseSource = null;

    // === SHORTENER TOGGLE ===
    const shortenerToggle = $('#shortener-toggle');
    const shortenerBody = $('#shortener-body');
    const shortenerChevron = $('#shortener-chevron');
    let shortenerOpen = true;
    shortenerToggle.addEventListener('click', () => {
        shortenerOpen = !shortenerOpen;
        shortenerBody.style.display = shortenerOpen ? 'flex' : 'none';
        shortenerChevron.textContent = shortenerOpen ? '▲' : '▼';
    });

    // === CREATE LINK ===
    const createForm = $('#create-link-form');
    const destInput = $('#dest-url-input');
    const createBtn = $('#create-btn');
    const linkResult = $('#link-result');
    const linkDisplay = $('#tracking-link-display');
    const copyBtn = $('#copy-link-btn');
    const disguisedBlock = $('#disguised-link-block');
    const disguisedDisplay = $('#disguised-link-display');
    const copyDisguisedBtn = $('#copy-disguised-btn');
    const disguiseDomainLabel = $('#disguise-domain-label');
    const aliasInput = $('#custom-alias-input');
    const disguiseSelect = $('#disguise-domain-select');

    createForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        let url = destInput.value.trim();
        if (!url) return;
        if (!url.startsWith('http://') && !url.startsWith('https://')) url = 'https://' + url;

        const customAlias = aliasInput.value.trim() || undefined;
        const disguiseDomain = disguiseSelect.value || undefined;

        createBtn.querySelector('.btn-text').hidden = true;
        createBtn.querySelector('.btn-loader').hidden = false;

        try {
            const res = await fetch('/api/tracker/create', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ destination: url, customAlias, disguiseDomain }),
            });
            const data = await res.json();
            if (data.error) throw new Error(data.error);

            const alias = data.alias || data.id;
            const realTrackUrl = `${window.location.origin}/s/${alias}`;
            linkDisplay.textContent = realTrackUrl;
            linkResult.hidden = false;

            // Show disguised link if a disguise domain was selected
            if (data.disguiseDomain) {
                const disguisedUrl = `https://${data.disguiseDomain}/${alias}`;
                disguisedDisplay.textContent = disguisedUrl;
                disguiseDomainLabel.textContent = data.disguiseDomain;
                disguisedBlock.hidden = false;
            } else {
                disguisedBlock.hidden = true;
            }

            // Reset inputs
            aliasInput.value = '';
            loadLinks();
        } catch (err) {
            alert('Failed to create link: ' + err.message);
        } finally {
            createBtn.querySelector('.btn-text').hidden = false;
            createBtn.querySelector('.btn-loader').hidden = true;
        }
    });

    copyBtn.addEventListener('click', () => {
        navigator.clipboard.writeText(linkDisplay.textContent);
        copyBtn.textContent = '✅ COPIED!';
        setTimeout(() => (copyBtn.textContent = '📋 COPY'), 2000);
    });

    copyDisguisedBtn.addEventListener('click', () => {
        navigator.clipboard.writeText(disguisedDisplay.textContent);
        copyDisguisedBtn.textContent = '✅ COPIED!';
        setTimeout(() => (copyDisguisedBtn.textContent = '📋 COPY'), 2000);
    });

    // === LOAD LINKS ===
    async function loadLinks() {
        try {
            const res = await fetch('/api/tracker/links');
            const links = await res.json();
            renderLinks(links);
        } catch { /* ignore */ }
    }

    function renderLinks(links) {
        const list = $('#links-list');
        const badge = $('#link-count-badge');
        badge.textContent = links.length;

        if (links.length === 0) {
            list.innerHTML = '<div class="empty-state"><div class="empty-icon">🔗</div><div class="empty-text">No tracking links yet. Create one above!</div></div>';
            return;
        }

        list.innerHTML = links.map((l) => `
      <div class="link-card${l.id === activeLinkId ? ' active' : ''}" data-id="${l.id}">
        <span class="link-card-id">${l.alias ? '/' + escapeHtml(l.alias) : '#' + l.id}</span>
        <span class="link-card-dest">${escapeHtml(l.destination)}</span>
        ${l.disguiseDomain ? '<span class="link-card-disguise">' + escapeHtml(l.disguiseDomain) + '</span>' : ''}
        <span class="link-card-visits">${l.visitCount} visits</span>
        <button class="link-card-delete" data-id="${l.id}" title="Delete">✕</button>
      </div>
    `).join('');

        // Click to open dashboard
        list.querySelectorAll('.link-card').forEach((card) => {
            card.addEventListener('click', (e) => {
                if (e.target.classList.contains('link-card-delete')) return;
                openDashboard(card.dataset.id);
            });
        });

        // Delete buttons
        list.querySelectorAll('.link-card-delete').forEach((btn) => {
            btn.addEventListener('click', async (e) => {
                e.stopPropagation();
                if (!confirm('Delete this tracking link?')) return;
                await fetch(`/api/tracker/${btn.dataset.id}`, { method: 'DELETE' });
                if (activeLinkId === btn.dataset.id) closeDashboard();
                loadLinks();
            });
        });
    }

    // === DASHBOARD ===
    async function openDashboard(linkId) {
        activeLinkId = linkId;
        const dashboard = $('#tracker-dashboard');
        dashboard.hidden = false;

        // Mark active card
        $$('.link-card').forEach((c) => c.classList.toggle('active', c.dataset.id === linkId));

        // Load visits
        try {
            const res = await fetch(`/api/tracker/${linkId}/visits`);
            const data = await res.json();
            if (data.error) return;
            renderDashboard(data.visits || []);
        } catch { /* ignore */ }

        // Start SSE
        if (sseSource) sseSource.close();
        sseSource = new EventSource(`/api/tracker/${linkId}/live`);
        sseSource.onmessage = (e) => {
            try {
                const visitOrUpdate = JSON.parse(e.data);
                if (visitOrUpdate.type === 'gps-update') {
                    // Update GPS for existing visit
                    updateVisitGPS(visitOrUpdate.visitId, visitOrUpdate.gps);
                } else {
                    // New visit
                    addVisitToLog(visitOrUpdate);
                    loadLinks(); // refresh visit counts
                }
            } catch { /* ignore */ }
        };
    }

    function closeDashboard() {
        activeLinkId = null;
        $('#tracker-dashboard').hidden = true;
        if (sseSource) { sseSource.close(); sseSource = null; }
    }

    function renderDashboard(visits) {
        updateStats(visits);
        renderMap(visits);
        renderDeviceBreakdown(visits);
        renderVisitLog(visits);
    }

    function updateStats(visits) {
        $('#dash-visit-count').textContent = visits.length;
        const uniqueIPs = new Set(visits.map((v) => v.ip));
        $('#dash-unique-count').textContent = uniqueIPs.size;
        const gpsCount = visits.filter((v) => v.gps).length;
        $('#dash-gps-count').textContent = gpsCount;
    }

    function renderMap(visits) {
        if (!trackerMap) {
            trackerMap = L.map('tracker-map-container', {
                center: [20, 0],
                zoom: 2,
                zoomControl: true,
                attributionControl: false,
            });
            L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
                maxZoom: 18,
            }).addTo(trackerMap);
        }

        // Clear old markers
        mapMarkers.forEach((m) => trackerMap.removeLayer(m));
        mapMarkers = [];

        visits.forEach((v) => {
            const lat = v.gps?.lat ?? v.geo?.lat;
            const lng = v.gps?.lng ?? v.geo?.lng;
            if (lat == null || lng == null) return;

            const isGPS = !!v.gps;
            const icon = L.divIcon({
                className: 'tracker-marker',
                html: `<div class="marker-dot ${isGPS ? 'gps' : 'ip'}"></div>`,
                iconSize: [16, 16],
                iconAnchor: [8, 8],
            });

            const marker = L.marker([lat, lng], { icon }).addTo(trackerMap);
            marker.bindPopup(`
        <div style="font-family:monospace;font-size:12px;">
          <b>${v.ip}</b><br/>
          ${v.geo?.city || 'Unknown'}, ${v.geo?.country || ''}<br/>
          ${v.browser} / ${v.os} / ${v.device}<br/>
          ${isGPS ? '📍 GPS: ' + lat.toFixed(4) + ', ' + lng.toFixed(4) : '🌐 IP-based location'}
        </div>
      `);
            mapMarkers.push(marker);
        });

        if (mapMarkers.length > 0) {
            const group = L.featureGroup(mapMarkers);
            trackerMap.fitBounds(group.getBounds().pad(0.2));
        }
    }

    function renderDeviceBreakdown(visits) {
        const total = visits.length || 1;
        const devices = { Desktop: 0, Mobile: 0, Tablet: 0 };
        const browsers = {};
        visits.forEach((v) => {
            devices[v.device] = (devices[v.device] || 0) + 1;
            browsers[v.browser] = (browsers[v.browser] || 0) + 1;
        });

        ['desktop', 'mobile', 'tablet'].forEach((d) => {
            const key = d.charAt(0).toUpperCase() + d.slice(1);
            const pct = Math.round(((devices[key] || 0) / total) * 100);
            const fill = $(`#fill-${d}`);
            const pctEl = $(`#pct-${d}`);
            if (fill) fill.style.width = pct + '%';
            if (pctEl) pctEl.textContent = pct + '%';
        });

        const browserDiv = $('#browser-breakdown');
        browserDiv.innerHTML = Object.entries(browsers)
            .sort((a, b) => b[1] - a[1])
            .map(([name, count]) => `<span class="browser-tag">${name}: ${count}</span>`)
            .join('');
    }

    function renderVisitLog(visits) {
        const tbody = $('#visit-log-body');
        tbody.innerHTML = '';
        visits.slice().reverse().forEach((v) => addVisitRow(v, false));
    }

    function addVisitRow(v, prepend = true) {
        const tbody = $('#visit-log-body');
        const tr = document.createElement('tr');
        const time = new Date(v.timestamp).toLocaleTimeString();
        const location = v.geo ? `${v.geo.city || '?'}, ${v.geo.country || '?'}` : 'Unknown';
        const gpsTag = v.gps
            ? `<span class="gps-tag precise">📍 ${v.gps.lat.toFixed(4)}, ${v.gps.lng.toFixed(4)}</span>`
            : `<span class="gps-tag ip-only">IP Only</span>`;
        tr.innerHTML = `
      <td>${time}</td>
      <td>${escapeHtml(v.ip)}</td>
      <td>${escapeHtml(location)}</td>
      <td>${escapeHtml(v.device || 'Unknown')}</td>
      <td>${escapeHtml(v.browser || 'Unknown')}</td>
      <td>${escapeHtml(v.os || 'Unknown')}</td>
      <td>${gpsTag}</td>
    `;
        if (prepend) tbody.prepend(tr);
        else tbody.appendChild(tr);
    }

    function addVisitToLog(visit) {
        addVisitRow(visit, true);
        // Update map
        const lat = visit.gps?.lat ?? visit.geo?.lat;
        const lng = visit.gps?.lng ?? visit.geo?.lng;
        if (lat != null && lng != null && trackerMap) {
            const isGPS = !!visit.gps;
            const icon = L.divIcon({
                className: 'tracker-marker',
                html: `<div class="marker-dot ${isGPS ? 'gps' : 'ip'} animate-in"></div>`,
                iconSize: [16, 16],
                iconAnchor: [8, 8],
            });
            const marker = L.marker([lat, lng], { icon }).addTo(trackerMap);
            mapMarkers.push(marker);
            trackerMap.setView([lat, lng], 6, { animate: true });
        }
        // Update stats
        const allRows = $$('#visit-log-body tr');
        $('#dash-visit-count').textContent = allRows.length;
    }

    function updateVisitGPS(visitId, gps) {
        // Re-render map with updated GPS
        // For simplicity, just add a new GPS marker
        if (trackerMap && gps) {
            const icon = L.divIcon({
                className: 'tracker-marker',
                html: `<div class="marker-dot gps animate-in"></div>`,
                iconSize: [16, 16],
                iconAnchor: [8, 8],
            });
            const marker = L.marker([gps.lat, gps.lng], { icon }).addTo(trackerMap);
            mapMarkers.push(marker);
        }
    }

    function escapeHtml(str) {
        if (!str) return '';
        return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    // Init
    loadLinks();
})();
