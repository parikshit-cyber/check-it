(function () {
    'use strict';
    const $ = (sel) => document.querySelector(sel);

    // Clock
    setInterval(() => { $('#live-clock').textContent = new Date().toTimeString().split(' ')[0]; }, 1000);
    $('#live-clock').textContent = new Date().toTimeString().split(' ')[0];

    // Particles
    (() => { const c = $('#particles'); if (!c) return; for (let i = 0; i < 40; i++) { const p = document.createElement('div'); p.className = 'particle'; p.style.left = Math.random() * 100 + '%'; p.style.animationDuration = (8 + Math.random() * 12) + 's'; p.style.animationDelay = (Math.random() * 10) + 's'; const s = (1 + Math.random() * 2) + 'px'; p.style.width = s; p.style.height = s; c.appendChild(p); } })();

    const dropzone = $('#meta-dropzone');
    const fileInput = $('#meta-file-input');
    const resultsSection = $('#meta-results');
    let metaMap = null;
    let currentImageData = null;

    // Dropzone events
    dropzone.addEventListener('click', () => fileInput.click());
    dropzone.addEventListener('dragover', (e) => { e.preventDefault(); dropzone.classList.add('dragover'); });
    dropzone.addEventListener('dragleave', () => dropzone.classList.remove('dragover'));
    dropzone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropzone.classList.remove('dragover');
        const file = e.dataTransfer.files[0];
        if (file && file.type.startsWith('image/')) processImage(file);
    });
    fileInput.addEventListener('change', () => {
        if (fileInput.files[0]) processImage(fileInput.files[0]);
    });

    async function processImage(file) {
        // Show preview
        const reader = new FileReader();
        reader.onload = (e) => {
            currentImageData = e.target.result;
            $('#meta-image-preview').src = currentImageData;
        };
        reader.readAsDataURL(file);

        // Extract EXIF
        const arrayBuffer = await file.arrayBuffer();
        const exifData = extractEXIF(new DataView(arrayBuffer));

        // Add file info
        exifData.unshift(
            { field: 'File Name', value: file.name, risk: 'low' },
            { field: 'File Size', value: formatBytes(file.size), risk: 'low' },
            { field: 'File Type', value: file.type, risk: 'low' },
            { field: 'Last Modified', value: file.lastModified ? new Date(file.lastModified).toLocaleString() : 'Unknown', risk: 'medium' },
        );

        renderResults(exifData);
    }

    function renderResults(metadata) {
        resultsSection.hidden = false;
        $('#meta-count').textContent = metadata.length + ' fields';

        // Check for GPS
        const gpsLat = metadata.find((m) => m.field === 'GPS Latitude');
        const gpsLng = metadata.find((m) => m.field === 'GPS Longitude');
        if (gpsLat && gpsLng) {
            const lat = parseFloat(gpsLat.value);
            const lng = parseFloat(gpsLng.value);
            if (!isNaN(lat) && !isNaN(lng)) {
                renderMap(lat, lng);
                $('#meta-coords').innerHTML = `📍 <strong>${lat.toFixed(6)}, ${lng.toFixed(6)}</strong> — This is where the photo was taken!`;
            }
        } else {
            $('#meta-coords').textContent = 'No GPS data found in this image';
            if (metaMap) {
                metaMap.setView([0, 0], 2);
            }
        }

        // Metadata table
        const tbody = $('#meta-table-body');
        tbody.innerHTML = metadata.map((m) => `
      <tr>
        <td>${m.field}</td>
        <td>${escapeHtml(String(m.value))}</td>
        <td><span class="risk-tag ${m.risk}">${m.risk}</span></td>
      </tr>
    `).join('');

        resultsSection.scrollIntoView({ behavior: 'smooth' });
    }

    function renderMap(lat, lng) {
        if (!metaMap) {
            metaMap = L.map('meta-map-container', { center: [lat, lng], zoom: 14, attributionControl: false });
            L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', { maxZoom: 18 }).addTo(metaMap);
        } else {
            metaMap.eachLayer((l) => { if (l instanceof L.Marker) metaMap.removeLayer(l); });
            metaMap.setView([lat, lng], 14);
        }

        const icon = L.divIcon({
            className: 'meta-marker',
            html: '<div style="width:16px;height:16px;border-radius:50%;background:#ff3366;box-shadow:0 0 12px #ff3366;border:2px solid #fff"></div>',
            iconSize: [16, 16], iconAnchor: [8, 8],
        });
        L.marker([lat, lng], { icon }).addTo(metaMap)
            .bindPopup(`<b>Photo Location</b><br/>${lat.toFixed(6)}, ${lng.toFixed(6)}`).openPopup();
    }

    // Strip metadata and download
    $('#meta-strip-btn').addEventListener('click', () => {
        if (!currentImageData) return;
        const img = new Image();
        img.onload = () => {
            const canvas = document.createElement('canvas');
            canvas.width = img.naturalWidth;
            canvas.height = img.naturalHeight;
            const ctx = canvas.getContext('2d');
            ctx.drawImage(img, 0, 0);
            canvas.toBlob((blob) => {
                const a = document.createElement('a');
                a.href = URL.createObjectURL(blob);
                a.download = 'clean_image.png';
                a.click();
                URL.revokeObjectURL(a.href);
            }, 'image/png');
        };
        img.src = currentImageData;
    });

    // === EXIF Parser (Pure JS) ===
    function extractEXIF(dataView) {
        const metadata = [];
        try {
            // Check for JPEG
            if (dataView.getUint16(0) !== 0xFFD8) {
                metadata.push({ field: 'Format', value: 'Not a JPEG — limited metadata extraction', risk: 'low' });
                return metadata;
            }

            let offset = 2;
            while (offset < dataView.byteLength - 4) {
                const marker = dataView.getUint16(offset);
                if (marker === 0xFFE1) { // APP1 (EXIF)
                    const length = dataView.getUint16(offset + 2);
                    const exifStart = offset + 4;

                    // Check for 'Exif\0\0'
                    if (dataView.getUint32(exifStart) === 0x45786966 && dataView.getUint16(exifStart + 4) === 0x0000) {
                        const tiffStart = exifStart + 6;
                        const bigEndian = dataView.getUint16(tiffStart) === 0x4D4D;

                        const getU16 = (o) => dataView.getUint16(o, !bigEndian);
                        const getU32 = (o) => dataView.getUint32(o, !bigEndian);

                        const ifdOffset = getU32(tiffStart + 4);
                        const ifd0Start = tiffStart + ifdOffset;

                        // Parse IFD0
                        parseIFD(dataView, ifd0Start, tiffStart, getU16, getU32, metadata, bigEndian);

                        // Look for EXIF sub-IFD
                        const exifIFDEntry = findTag(dataView, ifd0Start, tiffStart, getU16, getU32, 0x8769);
                        if (exifIFDEntry !== null) {
                            const exifIFDStart = tiffStart + exifIFDEntry;
                            parseIFD(dataView, exifIFDStart, tiffStart, getU16, getU32, metadata, bigEndian);
                        }

                        // Look for GPS IFD
                        const gpsIFDEntry = findTag(dataView, ifd0Start, tiffStart, getU16, getU32, 0x8825);
                        if (gpsIFDEntry !== null) {
                            const gpsIFDStart = tiffStart + gpsIFDEntry;
                            parseGPSIFD(dataView, gpsIFDStart, tiffStart, getU16, getU32, metadata, bigEndian);
                        }
                    }
                    break;
                }
                // Skip to next marker
                if ((marker & 0xFF00) !== 0xFF00) break;
                if (marker === 0xFFDA) break; // Start of scan, stop looking
                const segLength = dataView.getUint16(offset + 2);
                offset += 2 + segLength;
            }
        } catch (e) {
            metadata.push({ field: 'Parser Note', value: 'Some metadata could not be read: ' + e.message, risk: 'low' });
        }
        return metadata;
    }

    const EXIF_TAGS = {
        0x010F: { name: 'Camera Make', risk: 'medium' },
        0x0110: { name: 'Camera Model', risk: 'medium' },
        0x0112: { name: 'Orientation', risk: 'low' },
        0x011A: { name: 'X Resolution', risk: 'low' },
        0x011B: { name: 'Y Resolution', risk: 'low' },
        0x0131: { name: 'Software', risk: 'medium' },
        0x0132: { name: 'Date/Time', risk: 'high' },
        0x0213: { name: 'YCbCr Positioning', risk: 'low' },
        0x829A: { name: 'Exposure Time', risk: 'low' },
        0x829D: { name: 'F-Number', risk: 'low' },
        0x8827: { name: 'ISO Speed', risk: 'low' },
        0x9000: { name: 'EXIF Version', risk: 'low' },
        0x9003: { name: 'Date Taken', risk: 'high' },
        0x9004: { name: 'Date Digitized', risk: 'high' },
        0x920A: { name: 'Focal Length', risk: 'low' },
        0xA001: { name: 'Color Space', risk: 'low' },
        0xA002: { name: 'Image Width', risk: 'low' },
        0xA003: { name: 'Image Height', risk: 'low' },
        0xA405: { name: 'Focal Length (35mm)', risk: 'low' },
        0x9286: { name: 'User Comment', risk: 'high' },
        0xA420: { name: 'Unique Image ID', risk: 'critical' },
        0xA430: { name: 'Camera Owner', risk: 'critical' },
        0xA431: { name: 'Serial Number', risk: 'critical' },
        0xA432: { name: 'Lens Info', risk: 'low' },
        0xA433: { name: 'Lens Make', risk: 'low' },
        0xA434: { name: 'Lens Model', risk: 'low' },
    };

    function parseIFD(dataView, ifdStart, tiffStart, getU16, getU32, metadata, bigEndian) {
        try {
            const entries = getU16(ifdStart);
            for (let i = 0; i < entries; i++) {
                const entryOffset = ifdStart + 2 + i * 12;
                const tag = getU16(entryOffset);
                const type = getU16(entryOffset + 2);
                const count = getU32(entryOffset + 4);
                const valueOffset = entryOffset + 8;

                const tagInfo = EXIF_TAGS[tag];
                if (!tagInfo) continue;

                let value = readTagValue(dataView, type, count, valueOffset, tiffStart, getU32, bigEndian);
                if (value !== null) {
                    metadata.push({ field: tagInfo.name, value: value, risk: tagInfo.risk });
                }
            }
        } catch { /* ignore parse errors */ }
    }

    function findTag(dataView, ifdStart, tiffStart, getU16, getU32, targetTag) {
        try {
            const entries = getU16(ifdStart);
            for (let i = 0; i < entries; i++) {
                const entryOffset = ifdStart + 2 + i * 12;
                const tag = getU16(entryOffset);
                if (tag === targetTag) {
                    return getU32(entryOffset + 8);
                }
            }
        } catch { /* ignore */ }
        return null;
    }

    function parseGPSIFD(dataView, ifdStart, tiffStart, getU16, getU32, metadata, bigEndian) {
        try {
            const entries = getU16(ifdStart);
            let latRef = '', lngRef = '', lat = null, lng = null, alt = null;

            for (let i = 0; i < entries; i++) {
                const entryOffset = ifdStart + 2 + i * 12;
                const tag = getU16(entryOffset);
                const type = getU16(entryOffset + 2);
                const count = getU32(entryOffset + 4);
                const valueOffset = entryOffset + 8;

                switch (tag) {
                    case 1: // GPSLatitudeRef
                        latRef = readTagValue(dataView, type, count, valueOffset, tiffStart, getU32, bigEndian) || 'N';
                        break;
                    case 2: // GPSLatitude
                        lat = readGPSCoord(dataView, getU32(valueOffset), tiffStart, bigEndian);
                        break;
                    case 3: // GPSLongitudeRef
                        lngRef = readTagValue(dataView, type, count, valueOffset, tiffStart, getU32, bigEndian) || 'E';
                        break;
                    case 4: // GPSLongitude
                        lng = readGPSCoord(dataView, getU32(valueOffset), tiffStart, bigEndian);
                        break;
                    case 6: // GPSAltitude
                        alt = readRational(dataView, getU32(valueOffset), tiffStart, bigEndian);
                        break;
                }
            }

            if (lat !== null) {
                const latVal = (latRef === 'S' ? -1 : 1) * lat;
                metadata.push({ field: 'GPS Latitude', value: latVal.toFixed(6), risk: 'critical' });
            }
            if (lng !== null) {
                const lngVal = (lngRef === 'W' ? -1 : 1) * lng;
                metadata.push({ field: 'GPS Longitude', value: lngVal.toFixed(6), risk: 'critical' });
            }
            if (alt !== null) {
                metadata.push({ field: 'GPS Altitude', value: alt.toFixed(1) + ' m', risk: 'high' });
            }
        } catch { /* ignore */ }
    }

    function readGPSCoord(dataView, offset, tiffStart, bigEndian) {
        try {
            const absOffset = tiffStart + offset;
            const getU32 = (o) => dataView.getUint32(o, !bigEndian);
            const deg = getU32(absOffset) / getU32(absOffset + 4);
            const min = getU32(absOffset + 8) / getU32(absOffset + 12);
            const sec = getU32(absOffset + 16) / getU32(absOffset + 20);
            return deg + min / 60 + sec / 3600;
        } catch { return null; }
    }

    function readRational(dataView, offset, tiffStart, bigEndian) {
        try {
            const absOffset = tiffStart + offset;
            const getU32 = (o) => dataView.getUint32(o, !bigEndian);
            return getU32(absOffset) / getU32(absOffset + 4);
        } catch { return null; }
    }

    function readTagValue(dataView, type, count, valueOffset, tiffStart, getU32, bigEndian) {
        try {
            switch (type) {
                case 2: { // ASCII
                    const strOffset = count > 4 ? tiffStart + getU32(valueOffset) : valueOffset;
                    let str = '';
                    for (let i = 0; i < count - 1; i++) str += String.fromCharCode(dataView.getUint8(strOffset + i));
                    return str.trim();
                }
                case 3: // SHORT
                    return dataView.getUint16(valueOffset, !bigEndian);
                case 4: // LONG
                    return getU32(valueOffset);
                case 5: { // RATIONAL
                    const ratOffset = tiffStart + getU32(valueOffset);
                    return (getU32(ratOffset) / getU32(ratOffset + 4)).toFixed(4);
                }
                case 7: { // UNDEFINED
                    if (count <= 4) {
                        let str = '';
                        for (let i = 0; i < count; i++) str += String.fromCharCode(dataView.getUint8(valueOffset + i));
                        return str.trim() || null;
                    }
                    return `[${count} bytes]`;
                }
                default: return null;
            }
        } catch { return null; }
    }

    function escapeHtml(str) { return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'); }
    function formatBytes(b) { if (b >= 1e6) return (b / 1e6).toFixed(1) + ' MB'; if (b >= 1e3) return (b / 1e3).toFixed(0) + ' KB'; return b + ' B'; }
})();
