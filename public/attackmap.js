(function () {
    'use strict';
    const $ = (sel) => document.querySelector(sel);

    // State
    let attackMap = null;
    let attackTotal = 0;
    let attacksThisMinute = 0;
    const attackTypeCounts = {};
    const sourceCounts = {};
    const targetCounts = {};
    const arcsOnMap = [];
    const MAX_ARCS = 40;

    // Init map
    attackMap = L.map('attack-map', {
        center: [25, 10],
        zoom: 2.5,
        zoomControl: false,
        attributionControl: false,
        minZoom: 2,
        maxBoundsViscosity: 1.0,
    });

    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_nolabels/{z}/{x}/{y}{r}.png', {
        maxZoom: 18,
    }).addTo(attackMap);

    // SSE stream
    const evtSource = new EventSource('/api/attackmap/stream');
    evtSource.onmessage = (e) => {
        try {
            const batch = JSON.parse(e.data);
            if (Array.isArray(batch)) {
                batch.forEach(processAttack);
            }
        } catch { /* ignore */ }
    };

    function processAttack(attack) {
        attackTotal++;
        attacksThisMinute++;

        // Update counters
        attackTypeCounts[attack.type] = (attackTypeCounts[attack.type] || 0) + 1;
        sourceCounts[attack.source.country] = (sourceCounts[attack.source.country] || 0) + 1;
        targetCounts[attack.target.country] = (targetCounts[attack.target.country] || 0) + 1;

        // Draw arc
        drawAttackArc(attack);

        // Update UI
        updateCounters();
        updateSidebar(attack);
        addFeedItem(attack);
    }

    function drawAttackArc(attack) {
        const src = attack.source;
        const tgt = attack.target;

        // Create curved polyline (great circle approximation)
        const midLat = (src.lat + tgt.lat) / 2 + (Math.random() - 0.5) * 10;
        const midLng = (src.lng + tgt.lng) / 2 + (Math.random() - 0.5) * 10;
        const points = [
            [src.lat, src.lng],
            [midLat, midLng],
            [tgt.lat, tgt.lng],
        ];

        // Bezier-like curve
        const curvePoints = [];
        for (let t = 0; t <= 1; t += 0.05) {
            const lat = (1 - t) * (1 - t) * points[0][0] + 2 * (1 - t) * t * points[1][0] + t * t * points[2][0];
            const lng = (1 - t) * (1 - t) * points[0][1] + 2 * (1 - t) * t * points[1][1] + t * t * points[2][1];
            curvePoints.push([lat, lng]);
        }

        const polyline = L.polyline(curvePoints, {
            color: attack.color,
            weight: 2,
            opacity: 0.7,
            className: 'attack-arc',
            dashArray: '8 4',
        }).addTo(attackMap);

        // Impact dot at target
        const impactIcon = L.divIcon({
            className: 'impact-marker',
            html: `<div class="impact-dot" style="background:${attack.color};box-shadow:0 0 12px ${attack.color}"></div>`,
            iconSize: [8, 8],
            iconAnchor: [4, 4],
        });
        const impactMarker = L.marker([tgt.lat, tgt.lng], { icon: impactIcon }).addTo(attackMap);

        // Source dot
        const srcIcon = L.divIcon({
            className: 'src-marker',
            html: `<div style="width:5px;height:5px;border-radius:50%;background:${attack.color};opacity:0.6"></div>`,
            iconSize: [5, 5],
            iconAnchor: [2.5, 2.5],
        });
        const srcMarker = L.marker([src.lat, src.lng], { icon: srcIcon }).addTo(attackMap);

        arcsOnMap.push({ polyline, impactMarker, srcMarker });

        // Remove after 4 seconds
        setTimeout(() => {
            attackMap.removeLayer(polyline);
            attackMap.removeLayer(impactMarker);
            attackMap.removeLayer(srcMarker);
            const idx = arcsOnMap.findIndex((a) => a.polyline === polyline);
            if (idx !== -1) arcsOnMap.splice(idx, 1);
        }, 4000);

        // Keep max arcs on screen
        while (arcsOnMap.length > MAX_ARCS) {
            const old = arcsOnMap.shift();
            attackMap.removeLayer(old.polyline);
            attackMap.removeLayer(old.impactMarker);
            attackMap.removeLayer(old.srcMarker);
        }
    }

    function updateCounters() {
        $('#attack-total').textContent = attackTotal;
    }

    // Reset per-minute counter
    setInterval(() => {
        $('#attack-rate').textContent = attacksThisMinute;
        attacksThisMinute = 0;
    }, 60000);

    // Update rate display more frequently with estimate
    setInterval(() => {
        $('#attack-rate').textContent = attacksThisMinute;
    }, 5000);

    function updateSidebar(attack) {
        // Attack types
        const typeList = $('#attack-type-list');
        const sorted = Object.entries(attackTypeCounts).sort((a, b) => b[1] - a[1]);
        typeList.innerHTML = sorted.map(([type, count]) => {
            const color = getTypeColor(type);
            return `<div class="attack-type-row">
        <div class="attack-type-color" style="background:${color}"></div>
        <span class="attack-type-name">${type}</span>
        <span class="attack-type-count">${count}</span>
      </div>`;
        }).join('');

        // Top sources
        renderTopList('#top-sources', sourceCounts);
        // Top targets
        renderTopList('#top-targets', targetCounts);
    }

    function renderTopList(selector, counts) {
        const el = $(selector);
        const sorted = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 5);
        el.innerHTML = sorted.map(([name, count], idx) => `
      <div class="top-row">
        <span class="top-rank">${idx + 1}</span>
        <span class="top-name">${name}</span>
        <span class="top-count">${count}</span>
      </div>
    `).join('');
    }

    function addFeedItem(attack) {
        const feed = $('#live-feed');
        const item = document.createElement('div');
        item.className = 'feed-item';
        item.style.borderLeftColor = attack.color;
        const time = new Date().toTimeString().split(' ')[0];
        item.innerHTML = `
      <span class="feed-time">${time}</span>
      <span class="feed-type" style="color:${attack.color}">${attack.icon} ${attack.type}</span>
      <br/><span class="feed-route">${attack.source.city} → ${attack.target.city}</span>
    `;
        feed.prepend(item);

        // Keep max 50 items
        while (feed.children.length > 50) {
            feed.removeChild(feed.lastChild);
        }
    }

    const TYPE_COLORS = {
        'DDoS': '#ff3366', 'Brute Force': '#ff6633', 'Phishing': '#ffcc00',
        'Ransomware': '#ff0044', 'SQL Injection': '#ff9900', 'XSS': '#ff66cc',
        'Malware': '#cc00ff', 'Port Scan': '#00ccff', 'Data Exfiltration': '#ff0000',
        'Zero Day': '#ff0066', 'Man-in-the-Middle': '#ff6600', 'DNS Hijacking': '#00ff99',
    };
    function getTypeColor(type) { return TYPE_COLORS[type] || '#00ccff'; }
})();
