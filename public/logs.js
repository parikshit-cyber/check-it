/**
 * CHECK-IT — Log Analysis & Live Network Monitor Frontend
 * Handles:
 *  1) FILE UPLOAD mode — upload .log files for analysis with charts, tables, overlays
 *  2) LIVE MONITOR mode — real-time SSE packet capture with dashboard, protocol charts,
 *     website security grading, threat feed, and Wireshark-style packet table
 */

(function () {
    'use strict';

    const $ = (sel) => document.querySelector(sel);
    const $$ = (sel) => document.querySelectorAll(sel);

    // ═══════════════ CLOCK & THEME ═══════════════
    const liveClock = $('#live-clock');
    function updateClock() {
        const now = new Date();
        liveClock.textContent = [now.getHours(), now.getMinutes(), now.getSeconds()]
            .map(v => String(v).padStart(2, '0')).join(':');
    }
    setInterval(updateClock, 1000);
    updateClock();

    const themeToggle = $('#theme-toggle');
    function setTheme(theme) {
        document.documentElement.setAttribute('data-theme', theme);
        localStorage.setItem('checkit-theme', theme);
        themeToggle.classList.toggle('light', theme === 'light');
    }
    setTheme(localStorage.getItem('checkit-theme') || 'dark');
    themeToggle.addEventListener('click', () => {
        const current = document.documentElement.getAttribute('data-theme');
        setTheme(current === 'dark' ? 'light' : 'dark');
    });

    // Particles
    (function spawnParticles() {
        const container = $('#particles');
        if (!container) return;
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

    // ═══════════════ MODE SWITCHING ═══════════════
    const tabUpload = $('#tab-upload');
    const tabLive = $('#tab-live');
    const uploadSection = $('#log-upload-section');
    const logResults = $('#log-results');
    const liveSection = $('#live-monitor-section');
    let currentMode = 'upload';

    function switchMode(mode) {
        currentMode = mode;
        tabUpload.classList.toggle('active', mode === 'upload');
        tabLive.classList.toggle('active', mode === 'live');

        if (mode === 'upload') {
            liveSection.hidden = true;
            stopLiveCapture();
            // Show upload or results
            if (analysisData) {
                uploadSection.hidden = true;
                logResults.hidden = false;
            } else {
                uploadSection.hidden = false;
                logResults.hidden = true;
            }
        } else {
            uploadSection.hidden = true;
            logResults.hidden = true;
            liveSection.hidden = false;
        }
    }

    tabUpload.addEventListener('click', () => switchMode('upload'));
    tabLive.addEventListener('click', () => switchMode('live'));

    // ══════════════════════════════════════════════
    //   SECTION 1: FILE UPLOAD MODE
    // ══════════════════════════════════════════════
    let analysisData = null;
    let selectedFormat = 'auto';
    let currentPage = 1;
    const pageSize = 50;
    let sortColumn = null;
    let sortDir = 'asc';
    let filterSeverity = 'all';
    let searchQuery = '';
    let chartSeverity = null;
    let chartThreats = null;
    let chartTimeline = null;

    const logDropzone = $('#log-dropzone');
    const logFileInput = $('#log-file-input');
    const logLoading = $('#log-loading');
    const loadingStatus = $('#loading-status');
    const loadingProgress = $('#loading-progress');
    const entryFullscreen = $('#entry-fullscreen');
    const entryCloseBtn = $('#entry-close-btn');
    const newScanBtn = $('#new-scan-btn');
    const tableFilterSeverity = $('#table-filter-severity');
    const tableSearch = $('#table-search');

    // Format selector
    $$('.format-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            $$('.format-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            selectedFormat = btn.dataset.format;
        });
    });

    // File upload
    logDropzone.addEventListener('click', () => logFileInput.click());
    logFileInput.addEventListener('change', (e) => {
        if (e.target.files.length) handleLogFile(e.target.files[0]);
    });
    logDropzone.addEventListener('dragover', (e) => { e.preventDefault(); logDropzone.classList.add('dragover'); });
    logDropzone.addEventListener('dragleave', () => logDropzone.classList.remove('dragover'));
    logDropzone.addEventListener('drop', (e) => {
        e.preventDefault(); logDropzone.classList.remove('dragover');
        if (e.dataTransfer.files[0]) handleLogFile(e.dataTransfer.files[0]);
    });

    async function handleLogFile(file) {
        logDropzone.hidden = true;
        logLoading.hidden = false;
        loadingStatus.textContent = 'Uploading and parsing log file...';
        loadingProgress.style.width = '20%';
        const formData = new FormData();
        formData.append('logFile', file);
        formData.append('format', selectedFormat);
        try {
            loadingStatus.textContent = 'Analyzing entries for threats and vulnerabilities...';
            loadingProgress.style.width = '50%';
            const res = await fetch('/api/logs/analyze', { method: 'POST', body: formData });
            const data = await res.json();
            loadingProgress.style.width = '90%';
            loadingStatus.textContent = 'Building analysis dashboard...';
            if (data.error) { alert('Analysis error: ' + data.error); resetUpload(); return; }
            analysisData = data;
            loadingProgress.style.width = '100%';
            setTimeout(() => renderResults(data), 300);
        } catch (err) {
            console.error('Log analysis failed:', err);
            alert('Log analysis failed. Check server connection.');
            resetUpload();
        }
    }

    function resetUpload() {
        logDropzone.hidden = false;
        logLoading.hidden = true;
        logResults.hidden = true;
        uploadSection.hidden = false;
        logFileInput.value = '';
        loadingProgress.style.width = '0%';
    }

    newScanBtn.addEventListener('click', () => {
        analysisData = null;
        currentPage = 1;
        sortColumn = null;
        filterSeverity = 'all';
        searchQuery = '';
        tableFilterSeverity.value = 'all';
        tableSearch.value = '';
        destroyCharts();
        resetUpload();
    });

    entryCloseBtn.addEventListener('click', () => {
        entryFullscreen.hidden = true;
        document.body.style.overflow = '';
    });

    // ── Render the full analysis dashboard after file upload ──
    function renderResults(data) {
        logLoading.hidden = true;
        uploadSection.hidden = true;
        logResults.hidden = false;

        const summary = data.summary;

        // Update the circular risk gauge
        const circumference = 2 * Math.PI * 50;
        const gaugeOffset = circumference - (summary.overallRisk / 100) * circumference;
        const gaugeProgress = $('#gauge-progress');
        gaugeProgress.style.stroke = summary.riskColor;
        gaugeProgress.style.strokeDasharray = circumference;
        gaugeProgress.style.strokeDashoffset = gaugeOffset;

        $('#gauge-score').textContent = summary.overallRisk;
        $('#gauge-score').style.color = summary.riskColor;
        $('#gauge-level').textContent = summary.riskLevel.toUpperCase() + ' RISK';
        $('#gauge-level').style.color = summary.riskColor;
        $('#gauge-summary').textContent = `${summary.threatsFound} threats detected across ${summary.totalEntries} log entries`;

        // Update quick stats
        $('#stat-total').textContent = summary.totalEntries.toLocaleString();
        $('#stat-threats').textContent = summary.threatsFound.toLocaleString();
        $('#stat-critical').textContent = (summary.severityDistribution.critical || 0).toLocaleString();
        $('#stat-high').textContent = (summary.severityDistribution.high || 0).toLocaleString();
        $('#stat-medium').textContent = (summary.severityDistribution.medium || 0).toLocaleString();
        $('#stat-clean').textContent = (summary.totalEntries - summary.threatsFound).toLocaleString();

        // Update format info panel
        $('#info-format').textContent = data.format.toUpperCase();
        $('#info-time').textContent = new Date(data.analyzedAt).toLocaleTimeString();
        $('#info-entries').textContent = summary.totalEntries.toLocaleString();
        $('#info-risk').textContent = summary.riskLevel.toUpperCase();
        $('#info-risk').style.color = summary.riskColor;

        // Render all sub-components
        renderCharts(summary);
        renderTopIPs(summary.topIPs);
        renderMITRE(summary.topThreats);
        renderTable();
    }

    function destroyCharts() {
        if (chartSeverity) { chartSeverity.destroy(); chartSeverity = null; }
        if (chartThreats) { chartThreats.destroy(); chartThreats = null; }
        if (chartTimeline) { chartTimeline.destroy(); chartTimeline = null; }
    }

    function chartDefaults() {
        return {
            color: getComputedStyle(document.documentElement).getPropertyValue('--text-secondary').trim() || '#9494a1',
            gridColor: 'rgba(255,255,255,0.04)',
            font: { family: "'JetBrains Mono', monospace", size: 10 },
        };
    }

    function renderCharts(summary) {
        destroyCharts();
        const defaults = chartDefaults();

        // Severity distribution doughnut
        const severityData = [
            summary.severityDistribution.critical || 0,
            summary.severityDistribution.high || 0,
            summary.severityDistribution.medium || 0,
            summary.severityDistribution.low || 0,
            summary.severityDistribution.info || 0,
        ];
        const severityColors = [
            'rgba(255, 0, 110, 0.8)',   // Critical — magenta
            'rgba(255, 51, 102, 0.7)',  // High — red-pink
            'rgba(255, 184, 0, 0.7)',   // Medium — amber
            'rgba(0, 240, 255, 0.5)',   // Low — cyan
            'rgba(0, 255, 136, 0.4)',   // Info — green
        ];

        chartSeverity = new Chart($('#chart-severity'), {
            type: 'doughnut',
            data: {
                labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
                datasets: [{
                    data: severityData,
                    backgroundColor: severityColors,
                    borderWidth: 0,
                    hoverOffset: 10,
                }],
            },
            options: {
                responsive: true,
                cutout: '65%',
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: { color: defaults.color, font: defaults.font, padding: 12, usePointStyle: true },
                    },
                },
            },
        });

        // Top threats horizontal bar chart
        const topThreats = summary.topThreats.slice(0, 8);
        const barColors = ['#ff006e99', '#ff336699', '#ffb80099', '#00f0ff99', '#bc13fe99', '#00ff8899', '#ff884499', '#8080ff99'];

        chartThreats = new Chart($('#chart-threats'), {
            type: 'bar',
            data: {
                labels: topThreats.map(threat => threat.type),
                datasets: [{
                    data: topThreats.map(threat => threat.count),
                    backgroundColor: topThreats.map((_, index) => barColors[index % barColors.length]),
                    borderRadius: 4,
                    barThickness: 18,
                }],
            },
            options: {
                indexAxis: 'y',
                responsive: true,
                plugins: { legend: { display: false } },
                scales: {
                    x: { ticks: { color: defaults.color, font: defaults.font }, grid: { color: defaults.gridColor } },
                    y: { ticks: { color: defaults.color, font: { ...defaults.font, size: 9 } }, grid: { display: false } },
                },
            },
        });

        // Traffic timeline line chart
        const timeline = summary.timeline;

        chartTimeline = new Chart($('#chart-timeline'), {
            type: 'line',
            data: {
                labels: timeline.map(point => point.hour),
                datasets: [
                    {
                        label: 'Total',
                        data: timeline.map(point => point.total),
                        borderColor: '#00f0ff',
                        backgroundColor: 'rgba(0, 240, 255, 0.1)',
                        fill: true,
                        tension: 0.4,
                        pointRadius: 3,
                    },
                    {
                        label: 'Threats',
                        data: timeline.map(point => point.threats),
                        borderColor: '#ff006e',
                        backgroundColor: 'rgba(255, 0, 110, 0.1)',
                        fill: true,
                        tension: 0.4,
                        pointRadius: 3,
                    },
                ],
            },
            options: {
                responsive: true,
                interaction: { mode: 'index', intersect: false },
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: { color: defaults.color, font: defaults.font, usePointStyle: true },
                    },
                },
                scales: {
                    x: { ticks: { color: defaults.color, font: defaults.font }, grid: { color: defaults.gridColor } },
                    y: { ticks: { color: defaults.color, font: defaults.font }, grid: { color: defaults.gridColor } },
                },
            },
        });
    }

    function renderTopIPs(ips) {
        const container = $('#log-top-ips');

        if (!ips || !ips.length) {
            container.innerHTML = '<div class="ip-row"><span class="ip-addr">No source IPs</span></div>';
            return;
        }

        const maxCount = ips[0].count;

        container.innerHTML = ips.map(ip => `
            <div class="ip-row">
                <span class="ip-addr">${ip.ip}</span>
                <div class="ip-bar-wrap">
                    <div class="ip-bar" style="width:${(ip.count / maxCount * 100).toFixed(1)}%"></div>
                </div>
                <span class="ip-count">${ip.count}</span>
            </div>
        `).join('');
    }

    function renderMITRE(threats) {
        const container = $('#log-mitre');
        const threatsWithMitre = threats.filter(threat => threat.mitre);

        if (!threatsWithMitre.length) {
            container.innerHTML = '<div class="mitre-item"><span class="mitre-technique">No MITRE mappings</span></div>';
            return;
        }

        container.innerHTML = threatsWithMitre.map(threat => `
            <div class="mitre-item">
                <div class="mitre-header">
                    <span class="mitre-id">${threat.mitre.id}</span>
                    <span class="mitre-technique">${threat.mitre.technique}</span>
                    <span class="mitre-count">${threat.count}×</span>
                </div>
                <div class="mitre-tactic">Tactic: ${threat.mitre.tactic} • ${threat.type}</div>
            </div>
        `).join('');
    }

    /**
     * Applies severity filter, search query, and column sorting
     * to the raw analysis entries before rendering.
     */
    function getFilteredEntries() {
        if (!analysisData) return [];

        let entries = [...analysisData.entries];

        // Filter by severity level
        if (filterSeverity !== 'all') {
            entries = entries.filter(entry => entry.severity === filterSeverity);
        }

        // Filter by search query (matches IP, path, method, or threat names)
        if (searchQuery) {
            const query = searchQuery.toLowerCase();
            entries = entries.filter(entry => {
                const matchesIP = (entry.sourceIP || '').toLowerCase().includes(query);
                const matchesPath = (entry.path || '').toLowerCase().includes(query);
                const matchesMethod = (entry.method || '').toLowerCase().includes(query);
                const matchesThreat = (entry.threats || []).some(t => t.toLowerCase().includes(query));
                return matchesIP || matchesPath || matchesMethod || matchesThreat;
            });
        }

        // Sort by selected column
        if (sortColumn) {
            const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

            entries.sort((a, b) => {
                let valA = a[sortColumn] || '';
                let valB = b[sortColumn] || '';

                if (sortColumn === 'lineNumber') {
                    valA = Number(valA) || 0;
                    valB = Number(valB) || 0;
                }

                if (sortColumn === 'severity') {
                    valA = severityOrder[valA] ?? 5;
                    valB = severityOrder[valB] ?? 5;
                }

                if (valA < valB) return sortDir === 'asc' ? -1 : 1;
                if (valA > valB) return sortDir === 'asc' ? 1 : -1;
                return 0;
            });
        }

        return entries;
    }

    /**
     * Renders the log entry table with the current page of filtered entries.
     */
    function renderTable() {
        const entries = getFilteredEntries();
        const totalPages = Math.ceil(entries.length / pageSize) || 1;
        if (currentPage > totalPages) currentPage = totalPages;

        const startIndex = (currentPage - 1) * pageSize;
        const pageEntries = entries.slice(startIndex, startIndex + pageSize);
        const tbody = $('#log-table-body');

        tbody.innerHTML = pageEntries.map(entry => {
            const timestamp = entry.timestamp
                ? new Date(entry.timestamp).toLocaleString()
                : '—';

            const threatTags = entry.threats.length
                ? entry.threats.map(t => `<span class="threat-tag">${t}</span>`).join('')
                : '<span style="color:var(--text-dim);font-size:0.6rem">—</span>';

            return `
                <tr class="severity-${entry.severity}" data-id="${entry.id}">
                    <td>${entry.lineNumber}</td>
                    <td>${timestamp}</td>
                    <td style="color:var(--cyan)">${entry.sourceIP}</td>
                    <td>${entry.method}</td>
                    <td title="${entry.path}">${entry.path}</td>
                    <td><span class="severity-badge ${entry.severity}">${entry.severity.toUpperCase()}</span></td>
                    <td><div class="threat-tags">${threatTags}</div></td>
                </tr>
            `;
        }).join('');

        // Attach click handlers to each row for drill-down
        tbody.querySelectorAll('tr').forEach(row => {
            row.addEventListener('click', () => {
                const entry = analysisData.entries.find(e => e.id === row.dataset.id);
                if (entry) openEntryDetail(entry);
            });
        });

        renderPagination(totalPages, entries.length);

        // Update sort indicators on table headers
        $$('.log-table th.sortable').forEach(header => {
            header.classList.remove('sorted-asc', 'sorted-desc');
            if (header.dataset.sort === sortColumn) {
                header.classList.add(sortDir === 'asc' ? 'sorted-asc' : 'sorted-desc');
            }
        });
    }

    /**
     * Renders page navigation buttons below the log table.
     */
    function renderPagination(totalPages, totalEntries) {
        const container = $('#table-pagination');

        if (totalPages <= 1) {
            container.innerHTML = `<span style="font-family:var(--font-mono);font-size:0.65rem;color:var(--text-dim)">${totalEntries} entries</span>`;
            return;
        }

        let html = `<button class="page-btn" ${currentPage === 1 ? 'disabled' : ''} data-page="${currentPage - 1}">← PREV</button>`;

        // Calculate visible page range (max 5 buttons)
        const maxVisible = 5;
        let startPage = Math.max(1, currentPage - Math.floor(maxVisible / 2));
        let endPage = Math.min(totalPages, startPage + maxVisible - 1);
        if (endPage - startPage < maxVisible - 1) {
            startPage = Math.max(1, endPage - maxVisible + 1);
        }

        // First page + ellipsis if needed
        if (startPage > 1) {
            html += `<button class="page-btn" data-page="1">1</button>`;
            if (startPage > 2) html += `<span style="color:var(--text-dim);padding:0 4px">…</span>`;
        }

        // Page number buttons
        for (let i = startPage; i <= endPage; i++) {
            html += `<button class="page-btn ${i === currentPage ? 'active' : ''}" data-page="${i}">${i}</button>`;
        }

        // Last page + ellipsis if needed
        if (endPage < totalPages) {
            if (endPage < totalPages - 1) html += `<span style="color:var(--text-dim);padding:0 4px">…</span>`;
            html += `<button class="page-btn" data-page="${totalPages}">${totalPages}</button>`;
        }

        html += `<button class="page-btn" ${currentPage === totalPages ? 'disabled' : ''} data-page="${currentPage + 1}">NEXT →</button>`;

        container.innerHTML = html;

        // Attach click handlers to each pagination button
        container.querySelectorAll('.page-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                if (btn.disabled) return;
                currentPage = Number(btn.dataset.page);
                renderTable();
            });
        });
    }

    // ── Table sorting: click column headers to sort ──
    $$('.log-table th.sortable').forEach(header => {
        header.addEventListener('click', () => {
            const column = header.dataset.sort;
            if (sortColumn === column) {
                sortDir = sortDir === 'asc' ? 'desc' : 'asc';
            } else {
                sortColumn = column;
                sortDir = 'asc';
            }
            currentPage = 1;
            renderTable();
        });
    });

    // ── Table filtering by severity dropdown ──
    tableFilterSeverity.addEventListener('change', () => {
        filterSeverity = tableFilterSeverity.value;
        currentPage = 1;
        renderTable();
    });

    // ── Table search with debounce ──
    let searchDebounce;
    tableSearch.addEventListener('input', () => {
        clearTimeout(searchDebounce);
        searchDebounce = setTimeout(() => {
            searchQuery = tableSearch.value.trim();
            currentPage = 1;
            renderTable();
        }, 300);
    });

    // ── Entry Detail Overlay ──
    async function openEntryDetail(entry) {
        entryFullscreen.hidden = false;
        document.body.style.overflow = 'hidden';
        $('#entry-id-badge').textContent = `Line ${entry.lineNumber}`;

        try {
            const requestBody = {
                raw: entry.path || `${entry.method} ${entry.sourceIP} ${entry.path}`,
                format: analysisData.format,
                sourceIP: entry.sourceIP,
                timestamp: entry.timestamp,
                severity: entry.severity,
                threats: entry.threats,
            };

            const response = await fetch('/api/logs/entry/analyze', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(requestBody),
            });

            const detail = await response.json();

            if (detail.error) {
                renderEntryFallback(entry);
            } else {
                renderEntryDetail(detail, entry);
            }
        } catch (err) {
            renderEntryFallback(entry);
        }
    }

    /**
     * Renders the full entry detail overlay with risk gauge,
     * parsed fields, IOCs, vulnerabilities, and recommendations.
     */
    function renderEntryDetail(detail, tableEntry) {
        const riskColor = detail.severityColor || '#00f0ff';
        const circumference = 2 * Math.PI * 40;
        const offset = circumference - (detail.riskScore / 100) * circumference;
        const vulnCount = detail.totalVulnerabilities;

        // Risk gauge header
        $('#entry-risk-overview').innerHTML = `
            <div class="entry-risk-content">
                <div class="entry-risk-gauge">
                    <svg viewBox="0 0 100 100">
                        <circle class="track" cx="50" cy="50" r="40"/>
                        <circle class="progress" cx="50" cy="50" r="40"
                            stroke="${riskColor}"
                            stroke-dasharray="${circumference}"
                            stroke-dashoffset="${offset}"/>
                    </svg>
                    <div class="gauge-text">
                        <span class="gauge-score" style="color:${riskColor};font-size:1.3rem">${detail.riskScore}</span>
                        <span class="gauge-label">RISK</span>
                    </div>
                </div>
                <div class="entry-risk-info">
                    <h3 style="color:${riskColor}">${(detail.riskLevel || 'CLEAN').toUpperCase()} THREAT</h3>
                    <p>${vulnCount} vulnerabilit${vulnCount === 1 ? 'y' : 'ies'} detected</p>
                </div>
            </div>
        `;

        // Raw log line
        $('#entry-raw').textContent = detail.raw || tableEntry.path || '—';

        // Parsed fields
        const parsedFields = detail.parsedFields || {};
        let fieldsHtml = '';
        for (const [key, value] of Object.entries(parsedFields)) {
            if (key === 'raw' || key === 'index') continue;
            const displayValue = typeof value === 'object' ? JSON.stringify(value) : value;
            fieldsHtml += `
                <div class="parsed-field-row">
                    <span class="parsed-field-key">${key}</span>
                    <span class="parsed-field-value">${displayValue}</span>
                </div>
            `;
        }
        $('#entry-parsed').innerHTML = fieldsHtml || '<div class="parsed-field-row"><span class="parsed-field-key">No parsed fields</span></div>';

        // Indicators of Compromise (IOCs)
        const iocs = detail.iocs || {};
        let iocsHtml = '';
        for (const [type, values] of Object.entries(iocs)) {
            if (!values || !values.length) continue;
            values.forEach(val => {
                iocsHtml += `
                    <div class="ioc-item">
                        <span class="ioc-type">${type.toUpperCase()}</span>
                        <span class="ioc-value">${val}</span>
                    </div>
                `;
            });
        }
        $('#entry-iocs').innerHTML = iocsHtml
            || '<div class="ioc-item"><span class="ioc-type">NONE</span><span class="ioc-value" style="color:var(--text-dim)">No IOCs</span></div>';

        // Vulnerabilities
        const vulnerabilities = detail.vulnerabilities || [];
        const vulnContainer = $('#entry-vulnerabilities');

        if (vulnerabilities.length) {
            vulnContainer.innerHTML = vulnerabilities.map(vuln => {
                const sevColorMap = { critical: '#ff006e', high: '#ff3366', medium: '#ffb800', low: '#00f0ff' };
                const sevBgMap = { critical: 'rgba(255,0,110,0.15)', high: 'rgba(255,51,102,0.15)', medium: 'rgba(255,184,0,0.15)', low: 'rgba(0,240,255,0.1)' };
                const sevColor = sevColorMap[vuln.severity] || '#00ff88';
                const sevBg = sevBgMap[vuln.severity] || 'rgba(0,255,136,0.08)';

                const mitreHtml = vuln.mitre ? `
                    <div class="vuln-mitre">
                        <span class="vuln-mitre-id">${vuln.mitre.id}</span>
                        <span class="vuln-mitre-text">${vuln.mitre.tactic}: ${vuln.mitre.technique}</span>
                    </div>
                ` : '';

                const remediationHtml = (vuln.remediation && vuln.remediation.length) ? `
                    <div class="vuln-remediation-title">REMEDIATION</div>
                    ${vuln.remediation.map(step => `
                        <div class="vuln-remediation-item">
                            <span class="vuln-remediation-icon">▸</span>
                            <span>${step}</span>
                        </div>
                    `).join('')}
                ` : '';

                return `
                    <div class="vuln-card">
                        <div class="vuln-card-header">
                            <span class="vuln-type">${vuln.type}</span>
                            <span class="vuln-severity" style="background:${sevBg};color:${sevColor}">${vuln.severity.toUpperCase()}</span>
                        </div>
                        <div class="vuln-body">
                            <div class="vuln-detail">${vuln.detail}</div>
                            ${mitreHtml}
                            ${remediationHtml}
                        </div>
                    </div>
                `;
            }).join('');
        } else {
            vulnContainer.innerHTML = `
                <div class="log-card" style="padding:24px;text-align:center">
                    <div style="font-size:2rem;margin-bottom:12px">✅</div>
                    <div style="font-family:var(--font-mono);font-size:0.85rem;color:var(--text-primary)">NO VULNERABILITIES</div>
                </div>
            `;
        }

        // Recommendations
        const recommendations = detail.recommendations || [];
        const recContainer = $('#entry-recommendations');
        recContainer.innerHTML = recommendations.length
            ? recommendations.map(rec => `
                <div class="entry-rec-item">
                    <span class="entry-rec-icon">⚡</span>
                    <span>${rec}</span>
                </div>
            `).join('')
            : '<div class="entry-rec-item"><span class="entry-rec-icon">✓</span><span>No specific recommendations</span></div>';
    }

    /**
     * Fallback rendering when the backend detail API fails.
     * Shows basic info from the table entry data.
     */
    function renderEntryFallback(entry) {
        const riskColor = '#00f0ff';
        const scoreMap = { critical: 100, high: 75, medium: 50, low: 25, info: 5 };
        const riskScore = scoreMap[entry.severity] || 0;
        const circumference = 2 * Math.PI * 40;
        const offset = circumference - (riskScore / 100) * circumference;

        $('#entry-risk-overview').innerHTML = `
            <div class="entry-risk-content">
                <div class="entry-risk-gauge">
                    <svg viewBox="0 0 100 100">
                        <circle class="track" cx="50" cy="50" r="40"/>
                        <circle class="progress" cx="50" cy="50" r="40"
                            stroke="${riskColor}"
                            stroke-dasharray="${circumference}"
                            stroke-dashoffset="${offset}"/>
                    </svg>
                    <div class="gauge-text">
                        <span class="gauge-score" style="color:${riskColor};font-size:1.3rem">${riskScore}</span>
                        <span class="gauge-label">RISK</span>
                    </div>
                </div>
                <div class="entry-risk-info">
                    <h3 style="color:${riskColor}">${entry.severity.toUpperCase()}</h3>
                    <p>${entry.threatCount || entry.threats.length} threats</p>
                </div>
            </div>
        `;

        $('#entry-raw').textContent = entry.path || '—';

        $('#entry-parsed').innerHTML = `
            <div class="parsed-field-row">
                <span class="parsed-field-key">SOURCE IP</span>
                <span class="parsed-field-value">${entry.sourceIP}</span>
            </div>
            <div class="parsed-field-row">
                <span class="parsed-field-key">METHOD</span>
                <span class="parsed-field-value">${entry.method}</span>
            </div>
        `;

        $('#entry-iocs').innerHTML = (entry.sourceIP && entry.sourceIP !== '—')
            ? `<div class="ioc-item"><span class="ioc-type">IP</span><span class="ioc-value">${entry.sourceIP}</span></div>`
            : '<div class="ioc-item"><span class="ioc-type">NONE</span></div>';

        const vulnContainer = $('#entry-vulnerabilities');
        if (entry.threats.length) {
            vulnContainer.innerHTML = entry.threats.map(threat => `
                <div class="vuln-card">
                    <div class="vuln-card-header">
                        <span class="vuln-type">${threat}</span>
                        <span class="vuln-severity" style="background:rgba(255,0,110,0.15);color:#ff006e">DETECTED</span>
                    </div>
                    <div class="vuln-body">
                        <div class="vuln-detail">Threat at line ${entry.lineNumber}</div>
                    </div>
                </div>
            `).join('');
        } else {
            vulnContainer.innerHTML = `
                <div class="log-card" style="padding:24px;text-align:center">
                    <div style="font-size:2rem;margin-bottom:12px">✅</div>
                    <div style="font-family:var(--font-mono);font-size:0.85rem">CLEAN</div>
                </div>
            `;
        }

        $('#entry-recommendations').innerHTML = '<div class="entry-rec-item"><span class="entry-rec-icon">ℹ️</span><span>Full analysis unavailable</span></div>';
    }


    // ══════════════════════════════════════════════
    //   SECTION 2: LIVE NETWORK MONITOR
    // ══════════════════════════════════════════════
    let eventSource = null;
    let liveCapturing = false;
    let allPackets = [];
    let liveStats = { total: 0, threats: 0, connections: new Set(), dns: 0, encrypted: 0, bytes: 0, bytesSinceLastSecond: 0 };
    let protoCounts = {};
    let trafficTimeline = [];
    let timelineInterval = null;
    let bwInterval = null;
    let websiteMap = {};
    let threatFeedItems = [];
    let liveChartProto = null;
    let liveChartTraffic = null;
    const MAX_PACKETS_DISPLAY = 2000;
    const MAX_THREATS = 50;

    const liveStartBtn = $('#live-start-btn');
    const liveStopBtn = $('#live-stop-btn');
    const liveClearBtn = $('#live-clear-btn');
    const liveIndicator = $('#live-indicator');
    const liveStatusText = $('#live-status-text');
    const livePacketCounter = $('#live-packet-counter');
    const liveProtoFilter = $('#live-proto-filter');
    const liveSearchInput = $('#live-search');
    const liveAutoscroll = $('#live-autoscroll');
    const pktDetailOverlay = $('#packet-detail-overlay');
    const pktCloseBtn = $('#pkt-close-btn');

    liveStartBtn.addEventListener('click', startLiveCapture);
    liveStopBtn.addEventListener('click', stopLiveCapture);
    liveClearBtn.addEventListener('click', clearLiveData);
    pktCloseBtn.addEventListener('click', () => { pktDetailOverlay.hidden = true; document.body.style.overflow = ''; });

    function startLiveCapture() {
        if (liveCapturing) return;
        liveCapturing = true;
        liveStartBtn.disabled = true;
        liveStopBtn.disabled = false;
        liveIndicator.classList.add('capturing');
        liveStatusText.textContent = 'CAPTURING';

        eventSource = new EventSource('/api/logs/live-stream');
        eventSource.onmessage = (evt) => {
            try {
                const pkt = JSON.parse(evt.data);
                processPacket(pkt);
            } catch (err) { console.error('Packet parse error:', err); }
        };
        eventSource.onerror = () => {
            console.error('SSE connection error');
            stopLiveCapture();
        };

        // Timeline ticker — snapshot every 2 seconds
        timelineInterval = setInterval(() => {
            trafficTimeline.push({
                time: new Date().toLocaleTimeString('en-US', { hour12: false }),
                packets: liveStats.total,
                threats: liveStats.threats,
            });
            if (trafficTimeline.length > 30) trafficTimeline.shift();
            updateTrafficChart();
        }, 2000);

        // Bandwidth ticker
        bwInterval = setInterval(() => {
            const bw = liveStats.bytesSinceLastSecond;
            liveStats.bytesSinceLastSecond = 0;
            $('#ls-bandwidth').textContent = formatBytes(bw) + '/s';
        }, 1000);
    }

    function stopLiveCapture() {
        if (!liveCapturing && !eventSource) return;
        liveCapturing = false;
        if (eventSource) { eventSource.close(); eventSource = null; }
        liveStartBtn.disabled = false;
        liveStopBtn.disabled = true;
        liveIndicator.classList.remove('capturing');
        liveStatusText.textContent = 'STOPPED';
        if (timelineInterval) { clearInterval(timelineInterval); timelineInterval = null; }
        if (bwInterval) { clearInterval(bwInterval); bwInterval = null; }
    }

    function clearLiveData() {
        stopLiveCapture();
        allPackets = [];
        liveStats = { total: 0, threats: 0, connections: new Set(), dns: 0, encrypted: 0, bytes: 0, bytesSinceLastSecond: 0 };
        protoCounts = {};
        trafficTimeline = [];
        websiteMap = {};
        threatFeedItems = [];
        liveStatusText.textContent = 'IDLE';

        // Reset stats
        $('#ls-total-packets').textContent = '0';
        $('#ls-threats').textContent = '0';
        $('#ls-connections').textContent = '0';
        $('#ls-bandwidth').textContent = '0 B/s';
        $('#ls-dns').textContent = '0';
        $('#ls-secure').textContent = '0%';
        livePacketCounter.textContent = '0 packets';

        // Clear packet table
        $('#live-packet-body').innerHTML = '';

        // Clear lists
        $('#website-security-list').innerHTML = '<div class="ws-empty">Start capture to monitor connections</div>';
        $('#active-conn-list').innerHTML = '<div class="ws-empty">No connections yet</div>';
        $('#threat-feed-list').innerHTML = '<div class="ws-empty">No threats detected</div>';
        $('#conn-count').textContent = '0';

        // Destroy live charts
        if (liveChartProto) { liveChartProto.destroy(); liveChartProto = null; }
        if (liveChartTraffic) { liveChartTraffic.destroy(); liveChartTraffic = null; }
    }

    function processPacket(pkt) {
        allPackets.push(pkt);
        if (allPackets.length > MAX_PACKETS_DISPLAY * 2) allPackets = allPackets.slice(-MAX_PACKETS_DISPLAY);

        liveStats.total++;
        liveStats.bytes += pkt.length;
        liveStats.bytesSinceLastSecond += pkt.length;
        liveStats.connections.add(pkt.src + '→' + pkt.dst);

        // Protocol tracking
        protoCounts[pkt.protocol] = (protoCounts[pkt.protocol] || 0) + 1;

        // Encrypted tracking
        if (pkt.protocol === 'HTTPS' || pkt.protocol === 'SSH') liveStats.encrypted++;

        // DNS
        if (pkt.protocol === 'DNS') liveStats.dns++;

        // Threats
        if (pkt.threats.length) {
            liveStats.threats++;
            pkt.threats.forEach(t => {
                threatFeedItems.unshift({ type: t, detail: pkt.info, severity: pkt.severity, time: pkt.timeStr, domain: pkt.domain });
            });
            if (threatFeedItems.length > MAX_THREATS) threatFeedItems = threatFeedItems.slice(0, MAX_THREATS);
        }

        // Website tracking
        if (pkt.domain && (pkt.protocol === 'HTTP' || pkt.protocol === 'HTTPS' || pkt.protocol === 'DNS')) {
            if (!websiteMap[pkt.domain]) {
                websiteMap[pkt.domain] = { domain: pkt.domain, proto: pkt.protocol, tls: pkt.protocol === 'HTTPS', grade: pkt.protocol === 'HTTPS' ? 'A' : (pkt.protocol === 'HTTP' ? 'C' : 'B'), requests: 0, threats: 0 };
            }
            websiteMap[pkt.domain].requests++;
            if (pkt.threats.length) {
                websiteMap[pkt.domain].threats += pkt.threats.length;
                if (websiteMap[pkt.domain].threats > 2) websiteMap[pkt.domain].grade = 'F';
                else if (websiteMap[pkt.domain].threats > 0) websiteMap[pkt.domain].grade = 'D';
            }
        }

        // Update UI (throttled)
        updateLiveUI(pkt);
    }

    // Throttled UI updates
    let uiUpdatePending = false;
    function updateLiveUI(pkt) {
        // Always add to packet table
        addPacketRow(pkt);

        if (uiUpdatePending) return;
        uiUpdatePending = true;
        requestAnimationFrame(() => {
            uiUpdatePending = false;
            updateLiveStats();
            updateProtocolChart();
            updateWebsiteSecurity();
            updateActiveConnections();
            updateThreatFeed();
        });
    }

    function updateLiveStats() {
        $('#ls-total-packets').textContent = liveStats.total.toLocaleString();
        $('#ls-threats').textContent = liveStats.threats.toLocaleString();
        $('#ls-connections').textContent = liveStats.connections.size.toLocaleString();
        $('#ls-dns').textContent = liveStats.dns.toLocaleString();
        const encPct = liveStats.total ? Math.round(liveStats.encrypted / liveStats.total * 100) : 0;
        $('#ls-secure').textContent = encPct + '%';
        livePacketCounter.textContent = liveStats.total.toLocaleString() + ' packets';
    }

    function addPacketRow(pkt) {
        const filter = liveProtoFilter.value;
        const search = liveSearchInput.value.toLowerCase();
        if (filter !== 'all' && pkt.protocol !== filter) return;
        if (search && !pkt.info.toLowerCase().includes(search) && !pkt.src.includes(search) && !pkt.dst.includes(search) && !pkt.protocol.toLowerCase().includes(search)) return;

        const tbody = $('#live-packet-body');
        const tr = document.createElement('tr');
        tr.className = `proto-${pkt.protocol}${pkt.threats.length ? ' threat-row' : ''}`;
        tr.dataset.pktNo = pkt.no;

        const secBadge = pkt.security === 'secure' ? '<span class="pkt-security-badge secure">✓ SAFE</span>'
            : pkt.security === 'warning' ? '<span class="pkt-security-badge warning">⚠ WARN</span>'
                : '<span class="pkt-security-badge danger">✕ THREAT</span>';

        tr.innerHTML = `
      <td>${pkt.no}</td>
      <td>${pkt.timeStr}</td>
      <td>${pkt.src}</td>
      <td>${pkt.dst}</td>
      <td><span class="pkt-proto-badge conn-proto-badge ${pkt.protocol}">${pkt.protocol}</span></td>
      <td>${pkt.length}</td>
      <td title="${pkt.info}">${pkt.info}</td>
      <td>${secBadge}</td>
    `;

        tr.addEventListener('click', () => openPacketDetail(pkt));
        tbody.appendChild(tr);

        // Limit displayed rows
        while (tbody.children.length > MAX_PACKETS_DISPLAY) {
            tbody.removeChild(tbody.firstChild);
        }

        // Autoscroll
        if (liveAutoscroll.checked) {
            const wrap = $('#live-packet-wrap');
            wrap.scrollTop = wrap.scrollHeight;
        }
    }

    function updateProtocolChart() {
        const d = chartDefaults();
        const labels = Object.keys(protoCounts);
        const data = Object.values(protoCounts);
        const colors = { HTTP: '#00f0ff', HTTPS: '#00ff88', DNS: '#bc13fe', TCP: '#ffb800', UDP: '#8080ff', ICMP: '#ff8844', SSH: '#ff3366', FTP: '#ff006e' };

        if (!liveChartProto) {
            liveChartProto = new Chart($('#live-chart-proto'), {
                type: 'doughnut',
                data: {
                    labels,
                    datasets: [{ data, backgroundColor: labels.map(l => (colors[l] || '#666') + '99'), borderWidth: 0, hoverOffset: 8 }],
                },
                options: { responsive: true, cutout: '60%', plugins: { legend: { position: 'bottom', labels: { color: d.color, font: d.font, padding: 10, usePointStyle: true } } } },
            });
        } else {
            liveChartProto.data.labels = labels;
            liveChartProto.data.datasets[0].data = data;
            liveChartProto.data.datasets[0].backgroundColor = labels.map(l => (colors[l] || '#666') + '99');
            liveChartProto.update('none');
        }
    }

    function updateTrafficChart() {
        if (!trafficTimeline.length) return;
        const d = chartDefaults();
        const labels = trafficTimeline.map(t => t.time);

        // Calculate deltas
        const pktDeltas = trafficTimeline.map((t, i) => i === 0 ? t.packets : t.packets - trafficTimeline[i - 1].packets);
        const threatDeltas = trafficTimeline.map((t, i) => i === 0 ? t.threats : t.threats - trafficTimeline[i - 1].threats);

        if (!liveChartTraffic) {
            liveChartTraffic = new Chart($('#live-chart-traffic'), {
                type: 'line',
                data: {
                    labels,
                    datasets: [
                        { label: 'Packets/2s', data: pktDeltas, borderColor: '#00f0ff', backgroundColor: 'rgba(0,240,255,0.1)', fill: true, tension: 0.3, pointRadius: 2, borderWidth: 2 },
                        { label: 'Threats/2s', data: threatDeltas, borderColor: '#ff006e', backgroundColor: 'rgba(255,0,110,0.1)', fill: true, tension: 0.3, pointRadius: 2, borderWidth: 2 },
                    ],
                },
                options: {
                    responsive: true, animation: { duration: 0 },
                    plugins: { legend: { position: 'bottom', labels: { color: d.color, font: d.font, usePointStyle: true } } },
                    scales: { x: { ticks: { color: d.color, font: d.font, maxTicksLimit: 8 }, grid: { color: d.gridColor } }, y: { ticks: { color: d.color, font: d.font }, grid: { color: d.gridColor }, beginAtZero: true } },
                },
            });
        } else {
            liveChartTraffic.data.labels = labels;
            liveChartTraffic.data.datasets[0].data = pktDeltas;
            liveChartTraffic.data.datasets[1].data = threatDeltas;
            liveChartTraffic.update('none');
        }
    }

    function updateWebsiteSecurity() {
        const list = $('#website-security-list');
        const sites = Object.values(websiteMap).sort((a, b) => b.requests - a.requests).slice(0, 15);
        if (!sites.length) return;

        list.innerHTML = sites.map(s => {
            const tlsBadge = s.tls ? '<span class="ws-tls-badge secure">TLS</span>' : '<span class="ws-tls-badge insecure">PLAIN</span>';
            return `
        <div class="ws-item">
          <div class="ws-grade ${s.grade}">${s.grade}</div>
          <div class="ws-info">
            <div class="ws-domain">${s.domain}</div>
            <div class="ws-proto">${s.proto} • ${s.requests} requests${s.threats ? ` • ${s.threats} threats` : ''}</div>
          </div>
          ${tlsBadge}
        </div>
      `;
        }).join('');
    }

    function updateActiveConnections() {
        const connArr = Array.from(liveStats.connections);
        const recent = connArr.slice(-20).reverse();
        $('#conn-count').textContent = liveStats.connections.size;
        if (!recent.length) return;

        const list = $('#active-conn-list');
        list.innerHTML = recent.map(c => {
            const [src, dst] = c.split('→');
            const pkt = allPackets.findLast(p => p.src === src && p.dst === dst);
            const proto = pkt ? pkt.protocol : 'TCP';
            const bytes = pkt ? pkt.length : '—';
            return `
        <div class="conn-item">
          <span class="conn-proto-badge ${proto}">${proto}</span>
          <span class="conn-endpoints">${src}<span class="conn-arrow">→</span>${dst}</span>
          <span class="conn-bytes">${bytes}B</span>
        </div>
      `;
        }).join('');
    }

    function updateThreatFeed() {
        if (!threatFeedItems.length) return;
        const list = $('#threat-feed-list');
        list.innerHTML = threatFeedItems.slice(0, 20).map(t => `
      <div class="threat-feed-item">
        <div class="threat-feed-sev ${t.severity}"></div>
        <div class="threat-feed-body">
          <div class="threat-feed-type">${t.type}</div>
          <div class="threat-feed-detail">${t.detail}</div>
        </div>
        <span class="threat-feed-time">${t.time}</span>
      </div>
    `).join('');
    }

    // Packet detail overlay
    function openPacketDetail(pkt) {
        pktDetailOverlay.hidden = false;
        document.body.style.overflow = 'hidden';
        $('#pkt-id-badge').textContent = `Packet #${pkt.no}`;

        const color = pkt.security === 'danger' ? '#ff006e' : pkt.security === 'warning' ? '#ffb800' : '#00ff88';
        const score = pkt.security === 'danger' ? 85 : pkt.security === 'warning' ? 40 : 10;
        const C = 2 * Math.PI * 40, o = C - (score / 100) * C;

        $('#pkt-risk-overview').innerHTML = `
      <div class="entry-risk-content">
        <div class="entry-risk-gauge">
          <svg viewBox="0 0 100 100"><circle class="track" cx="50" cy="50" r="40"/><circle class="progress" cx="50" cy="50" r="40" stroke="${color}" stroke-dasharray="${C}" stroke-dashoffset="${o}"/></svg>
          <div class="gauge-text"><span class="gauge-score" style="color:${color};font-size:1.3rem">${score}</span><span class="gauge-label">RISK</span></div>
        </div>
        <div class="entry-risk-info">
          <h3 style="color:${color}">${pkt.security === 'danger' ? 'THREAT DETECTED' : pkt.security === 'warning' ? 'WARNING' : 'SECURE'}</h3>
          <p>${pkt.protocol} connection to ${pkt.domain || pkt.dst}</p>
          <p style="margin-top:4px;color:var(--text-dim)">Captured at ${pkt.timeStr}</p>
        </div>
      </div>
    `;

        // Connection details
        $('#pkt-conn-details').innerHTML = `
      <div class="parsed-field-row"><span class="parsed-field-key">SOURCE</span><span class="parsed-field-value">${pkt.src}</span></div>
      <div class="parsed-field-row"><span class="parsed-field-key">DESTINATION</span><span class="parsed-field-value">${pkt.dst}</span></div>
      <div class="parsed-field-row"><span class="parsed-field-key">PROTOCOL</span><span class="parsed-field-value">${pkt.protocol}</span></div>
      <div class="parsed-field-row"><span class="parsed-field-key">DOMAIN</span><span class="parsed-field-value">${pkt.domain || '—'}</span></div>
      <div class="parsed-field-row"><span class="parsed-field-key">LENGTH</span><span class="parsed-field-value">${pkt.length} bytes</span></div>
      <div class="parsed-field-row"><span class="parsed-field-key">INFO</span><span class="parsed-field-value" style="max-width:100%;white-space:normal">${pkt.info}</span></div>
    `;

        // Security analysis
        const securityDetails = getSecurityAnalysis(pkt);
        $('#pkt-security').innerHTML = securityDetails;

        // Vulnerabilities
        if (pkt.threats.length) {
            $('#pkt-vulnerabilities').innerHTML = pkt.threats.map(t => {
                const vuln = getVulnInfo(t, pkt);
                return `
          <div class="vuln-card" style="margin-bottom:12px">
            <div class="vuln-card-header">
              <span class="vuln-type">${t}</span>
              <span class="vuln-severity" style="background:rgba(255,0,110,0.15);color:#ff006e">${pkt.severity.toUpperCase()}</span>
            </div>
            <div class="vuln-body">
              <div class="vuln-detail">${vuln.detail}</div>
              ${vuln.mitre ? `<div class="vuln-mitre"><span class="vuln-mitre-id">${vuln.mitre.id}</span><span class="vuln-mitre-text">${vuln.mitre.technique}</span></div>` : ''}
              <div class="vuln-remediation-title">REMEDIATION</div>
              ${vuln.remediation.map(r => `<div class="vuln-remediation-item"><span class="vuln-remediation-icon">▸</span><span>${r}</span></div>`).join('')}
            </div>
          </div>
        `;
            }).join('');
        } else {
            $('#pkt-vulnerabilities').innerHTML = '<div style="padding:20px;text-align:center;font-family:var(--font-mono);font-size:0.8rem;color:#00ff88">✅ No vulnerabilities detected in this packet</div>';
        }

        // Recommendations
        const recs = getPacketRecommendations(pkt);
        $('#pkt-recommendations').innerHTML = recs.map(r => `<div class="entry-rec-item"><span class="entry-rec-icon">⚡</span><span>${r}</span></div>`).join('');
    }

    function getSecurityAnalysis(pkt) {
        const items = [];
        if (pkt.protocol === 'HTTPS') items.push({ label: 'ENCRYPTION', value: 'TLS Encrypted', ok: true });
        else if (pkt.protocol === 'HTTP') items.push({ label: 'ENCRYPTION', value: 'Unencrypted', ok: false });
        else if (pkt.protocol === 'SSH') items.push({ label: 'ENCRYPTION', value: 'SSH Encrypted', ok: true });
        else items.push({ label: 'ENCRYPTION', value: pkt.protocol + ' — N/A', ok: null });

        items.push({ label: 'DOMAIN REPUTATION', value: pkt.isSuspicious ? 'Suspicious/Malicious' : 'Clean', ok: !pkt.isSuspicious });
        items.push({ label: 'THREAT STATUS', value: pkt.threats.length ? `${pkt.threats.length} threat(s)` : 'Clean', ok: !pkt.threats.length });

        const ws = websiteMap[pkt.domain];
        if (ws) items.push({ label: 'SITE GRADE', value: ws.grade, ok: ws.grade === 'A' || ws.grade === 'B' });

        return items.map(i => {
            const color = i.ok === true ? '#00ff88' : i.ok === false ? '#ff006e' : 'var(--text-dim)';
            return `<div class="parsed-field-row"><span class="parsed-field-key">${i.label}</span><span class="parsed-field-value" style="color:${color}">${i.value}</span></div>`;
        }).join('');
    }

    function getVulnInfo(threat, pkt) {
        const vulnDB = {
            'SQL Injection': { detail: 'SQL injection payload detected in HTTP request parameters. Attacker attempting to extract or manipulate database.', mitre: { id: 'T1190', technique: 'Exploit Public-Facing Application' }, remediation: ['Implement parameterized queries', 'Deploy WAF rules for SQLi patterns', 'Input validation on all user inputs'] },
            'XSS Attack': { detail: 'Cross-Site Scripting payload detected. Attacker attempting to inject client-side scripts.', mitre: { id: 'T1059.007', technique: 'JavaScript Execution' }, remediation: ['Encode all output', 'Implement Content Security Policy headers', 'Use HTTPOnly cookies'] },
            'Path Traversal': { detail: 'Directory traversal attempt detected. Attacker trying to access system files outside webroot.', mitre: { id: 'T1083', technique: 'File and Directory Discovery' }, remediation: ['Sanitize file path inputs', 'Use chroot jails', 'Implement strict path validation'] },
            'Reconnaissance': { detail: 'Reconnaissance activity detected — probing for common admin panels and sensitive paths.', mitre: { id: 'T1595', technique: 'Active Scanning' }, remediation: ['Remove or restrict admin panels', 'Implement fail2ban', 'Monitor for scanning patterns'] },
            'DNS Tunneling': { detail: 'DNS tunneling detected — data exfiltration via DNS queries to suspicious domains.', mitre: { id: 'T1071.004', technique: 'DNS Protocol Abuse' }, remediation: ['Monitor DNS query lengths', 'Block queries to unknown TXT records', 'Implement DNS filtering'] },
            'Port Scan': { detail: 'Port scanning activity detected — attacker enumerating open ports for potential exploitation.', mitre: { id: 'T1046', technique: 'Network Service Scanning' }, remediation: ['Implement port-based rate limiting', 'Deploy IDS/IPS rules', 'Minimize exposed services'] },
            'Brute Force': { detail: 'Multiple authentication failures indicating brute-force login attempt.', mitre: { id: 'T1110', technique: 'Brute Force' }, remediation: ['Implement account lockout', 'Use multi-factor authentication', 'Deploy rate limiting on auth endpoints'] },
            'Suspicious Upload': { detail: 'Suspicious file upload detected — potential malware payload transfer.', mitre: { id: 'T1105', technique: 'Ingress Tool Transfer' }, remediation: ['Restrict file upload types', 'Scan uploads with AV', 'Isolate upload directory'] },
            'Malware Beacon': { detail: 'Command & Control beacon detected — host communicating with known malicious infrastructure.', mitre: { id: 'T1071', technique: 'Application Layer Protocol' }, remediation: ['Block C2 domain/IP', 'Isolate affected host', 'Run full system scan'] },
            'Data Exfiltration': { detail: 'Abnormally large outbound data transfer to suspicious destination.', mitre: { id: 'T1041', technique: 'Exfiltration Over C2 Channel' }, remediation: ['Implement DLP policies', 'Monitor outbound data volumes', 'Block unauthorized transfers'] },
            'Crypto Mining': { detail: 'Connection to known cryptocurrency mining pool detected.', mitre: { id: 'T1496', technique: 'Resource Hijacking' }, remediation: ['Block mining pool domains', 'Monitor CPU usage', 'Scan for mining software'] },
            'Deprecated TLS': { detail: 'Connection using deprecated TLS 1.0 — vulnerable to POODLE and BEAST attacks.', mitre: { id: 'T1557', technique: 'Adversary-in-the-Middle' }, remediation: ['Upgrade to TLS 1.2 or 1.3', 'Disable TLS 1.0/1.1', 'Update server certificates'] },
        };
        return vulnDB[threat] || { detail: `${threat} detected in ${pkt.protocol} traffic to ${pkt.domain}`, mitre: null, remediation: ['Investigate the connection', 'Block if malicious', 'Monitor for recurrence'] };
    }

    function getPacketRecommendations(pkt) {
        const recs = [];
        if (pkt.protocol === 'HTTP') recs.push('Upgrade this connection to HTTPS for encryption');
        if (pkt.isSuspicious) recs.push('Block the suspicious domain at the firewall level');
        if (pkt.threats.length) {
            recs.push('Investigate the source host for potential compromise');
            recs.push('Review network logs for related suspicious activity');
        }
        if (pkt.protocol === 'DNS' && pkt.threats.length) recs.push('Implement DNS filtering and DNSSEC');
        if (pkt.protocol === 'FTP') recs.push('Consider replacing FTP with SFTP for secure transfers');
        if (!recs.length) recs.push('No immediate action required — continue routine monitoring');
        return recs;
    }

    // Filter handlers for live
    liveProtoFilter.addEventListener('change', () => {
        refreshPacketTable();
    });

    let liveSearchDebounce;
    liveSearchInput.addEventListener('input', () => {
        clearTimeout(liveSearchDebounce);
        liveSearchDebounce = setTimeout(refreshPacketTable, 300);
    });

    function refreshPacketTable() {
        const tbody = $('#live-packet-body');
        tbody.innerHTML = '';
        const filter = liveProtoFilter.value;
        const search = liveSearchInput.value.toLowerCase();
        const filtered = allPackets.filter(p => {
            if (filter !== 'all' && p.protocol !== filter) return false;
            if (search && !p.info.toLowerCase().includes(search) && !p.src.includes(search) && !p.dst.includes(search)) return false;
            return true;
        }).slice(-MAX_PACKETS_DISPLAY);
        filtered.forEach(pkt => addPacketRow(pkt));
    }

    function formatBytes(bytes) {
        if (bytes < 1024) return bytes + ' B';
        if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
        return (bytes / 1024 / 1024).toFixed(1) + ' MB';
    }

})();
