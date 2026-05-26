/* ════════════════════════════════════════
   FRAUDSHIELD — script.js
   FULL CYBER GLOBE VERSION
════════════════════════════════════════ */

const API_BASE = "http://127.0.0.1:5000";

/* ─────────────────────────────────────
   GLOBAL STATE
───────────────────────────────────── */

let totalScanned = 0;
let totalThreats = 0;
let confSum = 0;

let trendData = [];

let severityCounts = {
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0
};

let domainCounts = {};

let lastScanData = null;

let scanHistory = [];

let chatHistory = [];

let world = null;

let attacks = [];


/* ════════════════════════════════════════
   INIT
════════════════════════════════════════ */

document.addEventListener('DOMContentLoaded', () => {

    initTheme();

    initThreatMap();

    waitForChartJs();

    /* ── AI chat Enter key ── */
    const chatInput = document.getElementById('chatInput');
    if (chatInput) {
        chatInput.addEventListener('keydown', e => {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                sendChat();
            }
        });
    }

    /* ── URL input Enter key ── */
    const urlInput = document.getElementById('urlInput');
    if (urlInput) {
        urlInput.addEventListener('keydown', e => {
            if (e.key === 'Enter') analyzeUrl();
        });
    }

    /* ── QR drag-and-drop ── */
    initQrZone();

    /* ── High score display on load ── */
    const hs = document.getElementById('gameHighScore');
    if (hs) hs.textContent = parseInt(localStorage.getItem('phishGameHS') || '0');
});


function waitForChartJs() {
    if (typeof Chart !== 'undefined') {
        initCharts();
    } else {
        setTimeout(waitForChartJs, 100);
    }
}


/* ════════════════════════════════════════
   THEME
════════════════════════════════════════ */

function initTheme() {
    const saved = localStorage.getItem('fraudshield-theme') || 'dark';
    applyTheme(saved);
}

function toggleTheme() {
    const current = document.documentElement.getAttribute('data-theme');
    applyTheme(current === 'dark' ? 'light' : 'dark');
}

function applyTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('fraudshield-theme', theme);

    const icon  = document.getElementById('themeIcon');
    const label = document.getElementById('themeLabel');
    if (icon)  icon.textContent  = theme === 'dark' ? '☀' : '☾';
    if (label) label.textContent = theme === 'dark' ? 'Light Mode' : 'Dark Mode';
}


/* ════════════════════════════════════════
   NAVIGATION
   FIX: pageTitle was never updated; 'game' section was unreachable
════════════════════════════════════════ */

const PAGE_TITLES = {
    dashboard: 'Dashboard',
    scan:      'Scan',
    analytics: 'Analytics',
    threatmap: 'Threat Map',
    history:   'History',
    chat:      'AI Analyst',
    game:      'Spot the Phish',
};

function navigate(section, el) {

    document
        .querySelectorAll('.page-section')
        .forEach(s => s.classList.remove('active'));

    document
        .querySelectorAll('.nav-item')
        .forEach(n => n.classList.remove('active'));

    const target = document.getElementById(`section-${section}`);
    if (target) target.classList.add('active');
    if (el)     el.classList.add('active');

    /* FIX: update topbar title */
    const titleEl = document.getElementById('pageTitle');
    if (titleEl) titleEl.textContent = PAGE_TITLES[section] || section;

    /* Close mobile sidebar after navigation */
    const sidebar = document.getElementById('sidebar');
    if (sidebar) sidebar.classList.remove('open');

    if (section === 'threatmap') {
        setTimeout(() => {
            if (!world) initThreatMap();
        }, 200);
    }
}


/* ════════════════════════════════════════
   URL ANALYSIS
════════════════════════════════════════ */

async function analyzeUrl() {

    const url = document.getElementById('urlInput').value.trim();

    if (!url) {
        showToast('Enter a URL');
        return;
    }

    showScanOverlay(true);

    try {
        const res = await fetch(`${API_BASE}/api/analyze/url`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url })
        });

        const data = await res.json();
        showScanOverlay(false);
        updateDashboard(data);

    } catch (err) {
        showScanOverlay(false);
        showToast('Could not connect to backend');
    }
}


/* ════════════════════════════════════════
   DASHBOARD UPDATE
════════════════════════════════════════ */

function updateDashboard(data) {

    const pct  = Math.round((data.fraud_probability || 0) * 100);
    const risk = data.risk_level || 'LOW';

    document.getElementById('gaugePct').textContent  = `${pct}%`;
    document.getElementById('gaugeRisk').textContent = risk;

    totalScanned++;
    if (risk !== 'LOW') totalThreats++;

    document.getElementById('totalScanned').textContent = totalScanned;
    document.getElementById('totalThreats').textContent = totalThreats;
    document.getElementById('topScanned').textContent   = totalScanned;

    /* avg confidence */
    if (data.confidence) {
        confSum += data.confidence;
        const avg = Math.round((confSum / totalScanned) * 100);
        const confEl = document.getElementById('avgConfidence');
        if (confEl) confEl.textContent = avg + '%';
    }

    renderFlags(data.flags || []);
    renderFeatures(data.features || {});

    if (data.id) {
        renderFeedbackBar(data.id);
    }

    addToHistory(data);
    addThreatFromScan(risk);

    /* update domain count */
    try {
        const host = new URL(data.url || '').hostname;
        domainCounts[host] = (domainCounts[host] || 0) + 1;
    } catch {}

    updateCharts(risk, pct);

    lastScanData = data;
}


/* ════════════════════════════════════════
   FLAGS
════════════════════════════════════════ */

function renderFlags(flags) {

    const box = document.getElementById('flagsList');
    if (!box) return;
    box.innerHTML = '';

    if (!flags.length) {
        box.innerHTML = '<div class="flag-item flag-safe">No threats detected</div>';
        return;
    }

    flags.forEach(flag => {
        const div = document.createElement('div');
        div.className   = 'flag-item';
        div.textContent = flag;
        box.appendChild(div);
    });
}

function addToHistory(data) {
    const accordion = document.getElementById('historyAccordion');
    if (!accordion) return;

    const risk = (data.risk_level || 'LOW').toUpperCase();
    const safeClass = risk === 'LOW' ? 'history-safe' : 'history-unsafe';
    const badgeText = risk === 'LOW' ? 'SAFE' : 'UNSAFE';

    const historyItem = {
        id: data.id || Date.now(),
        url: data.url || 'Unknown URL',
        risk,
        probability: Math.round((data.fraud_probability || 0) * 100),
        flags: data.flags || [],
        timestamp: new Date().toLocaleString()
    };

    scanHistory.unshift(historyItem);

    accordion.innerHTML = scanHistory.map(scan => `
        <div class="accordion-item ${scan.risk === 'LOW' ? 'history-safe' : 'history-unsafe'}">
            <div class="accordion-header">
                <div class="history-left">
                    <div class="history-url">${scan.url}</div>
                    <div class="history-time">${scan.timestamp}</div>
                </div>
                <div class="history-right">
                    <div class="history-badge ${scan.risk === 'LOW' ? 'history-safe' : 'history-unsafe'}">
                        ${scan.risk === 'LOW' ? 'SAFE' : 'UNSAFE'}
                    </div>
                    <div class="history-percent">${scan.probability}%</div>
                </div>
            </div>
            <div class="accordion-body">
                <strong>Threat Indicators:</strong>
                <ul class="history-flags">
                    ${scan.flags.length
                        ? scan.flags.map(flag => `<li>${flag}</li>`).join('')
                        : '<li>No threats detected</li>'}
                </ul>
            </div>
        </div>
    `).join('');
}


/* ════════════════════════════════════════
   FEATURES
════════════════════════════════════════ */

function renderFeatures(features) {

    const grid = document.getElementById('featureGrid');
    if (!grid) return;
    grid.innerHTML = '';

    Object.entries(features).forEach(([key, value]) => {
        grid.innerHTML += `
            <div class="feat-cell">
                <div class="feat-name">${key.replaceAll('_', ' ')}</div>
                <div class="feat-val">${value}</div>
            </div>
        `;
    });
}


/* ════════════════════════════════════════
   CHARTS
════════════════════════════════════════ */

let trendChartInst     = null;
let trendChartFullInst = null;
let pieChartInst       = null;
let pieChartFullInst   = null;

function mkLineChart(el, color) {
    if (!el) return null;
    return new Chart(el, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                data: [],
                borderColor: color || '#4f90ff',
                backgroundColor: (color || '#4f90ff') + '22',
                fill: true,
                tension: 0.4,
                pointRadius: 3,
                pointBackgroundColor: color || '#4f90ff'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: { duration: 400 },
            plugins: { legend: { display: false } },
            scales: {
                x: { display: false },
                y: { display: false, min: 0, max: 100 }
            }
        }
    });
}

function mkPieChart(el) {
    if (!el) return null;
    return new Chart(el, {
        type: 'doughnut',
        data: {
            labels: ['HIGH', 'MEDIUM', 'LOW'],
            datasets: [{
                data: [0, 0, 0],
                backgroundColor: ['#ff3d5a', '#ffb020', '#20d0a0'],
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: { duration: 400 },
            plugins: {
                legend: {
                    display: true,
                    position: 'bottom',
                    labels: { color: '#7070a0', font: { size: 11 }, padding: 10 }
                }
            },
            cutout: '68%'
        }
    });
}

function initCharts() {
    trendChartInst     = mkLineChart(document.getElementById('trendChart'),     '#4f90ff');
    trendChartFullInst = mkLineChart(document.getElementById('trendChartFull'), '#4f90ff');
    pieChartInst       = mkPieChart(document.getElementById('pieChart'));
    pieChartFullInst   = mkPieChart(document.getElementById('pieChartFull'));
}

function updateCharts(riskLevel, pct) {

    const label = new Date().toLocaleTimeString();

    [trendChartInst, trendChartFullInst].forEach(c => {
        if (!c) return;
        c.data.labels.push(label);
        c.data.datasets[0].data.push(pct);
        if (c.data.labels.length > 20) {
            c.data.labels.shift();
            c.data.datasets[0].data.shift();
        }
        c.update('none');
    });

    const idx = riskLevel === 'HIGH' ? 0 : riskLevel === 'MEDIUM' ? 1 : 2;
    [pieChartInst, pieChartFullInst].forEach(c => {
        if (!c) return;
        c.data.datasets[0].data[idx]++;
        c.update('none');
    });

    updateTopDomains();
}

function updateTopDomains() {
    const sorted = Object.entries(domainCounts)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 5);

    ['topDomainsList', 'topDomainsListFull'].forEach(id => {
        const el = document.getElementById(id);
        if (!el) return;
        if (!sorted.length) {
            el.innerHTML = '<div class="empty-state">No scans yet</div>';
            return;
        }
        el.innerHTML = sorted.map(([d, n]) =>
            `<div class="domain-row">
                <span class="domain-name">${d}</span>
                <span class="domain-count">${n}</span>
            </div>`
        ).join('');
    });
}


/* ════════════════════════════════════════
   CYBER ATTACK GLOBE
════════════════════════════════════════ */

function initThreatMap() {

    const globeContainer = document.getElementById('globeViz');
    if (!globeContainer || world) return;

    world = Globe()(globeContainer)
        .globeImageUrl('https://unpkg.com/three-globe/example/img/earth-night.jpg')
        .bumpImageUrl('https://unpkg.com/three-globe/example/img/earth-topology.png')
        .backgroundColor('#020617')
        .showAtmosphere(true)
        .atmosphereColor('#00e5ff')
        .atmosphereAltitude(0.22)
        .arcColor(d => d.color)
        .arcDashLength(0.35)
        .arcDashGap(4)
        .arcDashAnimateTime(1800)
        .arcStroke(0.45)
        .arcsTransitionDuration(0)
        .pointColor(d => d.color)
        .pointAltitude(0.015)
        .pointRadius(0.25)
        .pointsMerge(true);

    world.pointOfView({ lat: 15, lng: 10, altitude: 3.2 }, 0);
    world.controls().autoRotate      = true;
    world.controls().autoRotateSpeed = 0.22;
    world.controls().minDistance     = 180;
    world.controls().maxDistance     = 320;

    for (let i = 0; i < 18; i++) createAttack();

    setInterval(createAttack, 900);
}


/* ─────────────────────────────────────
   CITY DATA
───────────────────────────────────── */

const CYBER_CITIES = [
    { name: 'New York',   lat:  40.7128, lng:  -74.0060 },
    { name: 'London',     lat:  51.5072, lng:   -0.1276 },
    { name: 'Tokyo',      lat:  35.6762, lng:  139.6503 },
    { name: 'Moscow',     lat:  55.7558, lng:   37.6173 },
    { name: 'Singapore',  lat:   1.3521, lng:  103.8198 },
    { name: 'Sydney',     lat: -33.8688, lng:  151.2093 },
    { name: 'Dubai',      lat:  25.2048, lng:   55.2708 },
    { name: 'Berlin',     lat:  52.5200, lng:   13.4050 },
    { name: 'Mumbai',     lat:  19.0760, lng:   72.8777 },
    { name: 'São Paulo',  lat: -23.5505, lng:  -46.6333 },
    { name: 'Beijing',    lat:  39.9042, lng:  116.4074 },
    { name: 'Los Angeles',lat:  34.0522, lng: -118.2437 },
];


/* ─────────────────────────────────────
   ATTACK GENERATOR
───────────────────────────────────── */

function createAttack() {

    if (!world) return;

    const start = CYBER_CITIES[Math.floor(Math.random() * CYBER_CITIES.length)];
    const end   = CYBER_CITIES[Math.floor(Math.random() * CYBER_CITIES.length)];
    if (start.name === end.name) return;

    const threatTypes = [
        { type: 'PHISHING', color: '#FFD700' },
        { type: 'MALWARE',  color: '#ff4444' },
        { type: 'BOTNET',   color: '#ff8800' },
        { type: 'QR SCAM',  color: '#00e5ff' },
    ];

    const threat = threatTypes[Math.floor(Math.random() * threatTypes.length)];

    attacks.push({
        startLat: start.lat, startLng: start.lng,
        endLat:   end.lat,   endLng:   end.lng,
        color:    threat.color,
        altitude: 0.12 + Math.random() * 0.15
    });

    if (attacks.length > 80) attacks.shift();

    world.arcsData(attacks);
    world.pointsData([
        { lat: start.lat, lng: start.lng, color: threat.color },
        { lat: end.lat,   lng: end.lng,   color: threat.color },
    ]);

    addThreatFeed(`${threat.type}: ${start.name} → ${end.name}`);
}


/* ─────────────────────────────────────
   SCAN TRIGGERED ATTACKS
───────────────────────────────────── */

function addThreatFromScan(risk) {
    if (risk === 'LOW') return;
    createAttack();
}


/* ─────────────────────────────────────
   THREAT FEED
───────────────────────────────────── */

function addThreatFeed(message) {

    const feed = document.getElementById('threatFeed');
    if (!feed) return;

    const item = document.createElement('div');
    item.className = 'threat-feed-item';
    item.innerHTML = `<span class="threat-dot"></span>${message}`;
    feed.prepend(item);

    while (feed.children.length > 8) {
        feed.removeChild(feed.lastChild);
    }
}


/* ════════════════════════════════════════
   AI CHAT
════════════════════════════════════════ */

async function sendChat() {

    const input = document.getElementById('chatInput');
    const msg   = input.value.trim();
    if (!msg) return;

    input.value = '';
    appendMsg(msg, 'user');

    try {
        const res = await fetch(`${API_BASE}/api/chat`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                message: msg,
                context: lastScanData ? JSON.stringify(lastScanData) : ''
            })
        });

        const data = await res.json();
        appendMsg(data.reply || 'No response', 'ai');

    } catch {
        appendMsg('AI backend unavailable', 'ai');
    }
}


function appendMsg(text, role) {

    const box = document.getElementById('chatMessages');
    if (!box) return;

    const div = document.createElement('div');
    div.className = `chat-msg ${role}-msg`;
    div.innerHTML = `<div class="msg-bubble">${text}</div>`;
    box.appendChild(div);
    box.scrollTop = box.scrollHeight;
}


function clearHistory() {
    scanHistory = [];

    const accordion = document.getElementById('historyAccordion');
    if (accordion) {
        accordion.innerHTML = '<div class="history-empty">No scans recorded yet</div>';
    }

    showToast('History cleared');
}


/* ════════════════════════════════════════
   CHAT CLEAR
   FIX: clearChat() was called in HTML but never defined
════════════════════════════════════════ */

function clearChat() {
    const box = document.getElementById('chatMessages');
    if (box) {
        box.innerHTML = `
            <div class="chat-msg ai-msg">
                <div class="msg-bubble">Hello! I'm your AI Security Analyst.</div>
            </div>
        `;
    }
    chatHistory = [];
    showToast('Chat cleared');
}


/* ════════════════════════════════════════
   UTILITIES
════════════════════════════════════════ */

function showToast(msg) {

    const toast = document.getElementById('toast');
    if (!toast) return;

    toast.textContent = msg;
    toast.classList.add('show');

    clearTimeout(toast._timer);
    toast._timer = setTimeout(() => {
        toast.classList.remove('show');
    }, 3000);
}


function showScanOverlay(visible) {

    const overlay = document.getElementById('scanOverlay');
    if (!overlay) return;

    if (visible) {
        overlay.classList.add('active');
    } else {
        overlay.classList.remove('active');
    }
}


/* ════════════════════════════════════════
   MOBILE SIDEBAR
════════════════════════════════════════ */

function toggleSidebar() {
    const sidebar = document.getElementById('sidebar');
    if (sidebar) sidebar.classList.toggle('open');
}


/* ════════════════════════════════════════
   FEEDBACK — thumbs up / down
════════════════════════════════════════ */

let lastScanId = null;


function renderFeedbackBar(scanId) {

    lastScanId = scanId;

    const existing = document.getElementById('feedbackBar');
    if (existing) existing.remove();

    const bar = document.createElement('div');
    bar.id        = 'feedbackBar';
    bar.className = 'feedback-bar';
    bar.innerHTML = `
        <span class="feedback-label">Was this result accurate?</span>
        <div class="feedback-btns">
            <button class="feedback-btn thumb-up"
                onclick="submitFeedback(${scanId}, 'correct')">
                👍 Correct
            </button>
            <button class="feedback-btn thumb-down"
                onclick="submitFeedback(${scanId}, 'wrong')">
                👎 Wrong
            </button>
        </div>
    `;

    const flagsCard = document.getElementById('flagsList')?.closest('.neu-card');
    if (flagsCard) flagsCard.appendChild(bar);
}


async function submitFeedback(scanId, vote) {

    const bar = document.getElementById('feedbackBar');
    if (bar) bar.querySelectorAll('.feedback-btn').forEach(b => b.disabled = true);

    try {
        const res = await fetch(`${API_BASE}/api/feedback/${scanId}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ vote })
        });

        const data = await res.json();

        if (!res.ok) {
            showToast(data.error || 'Feedback failed');
            if (bar) bar.querySelectorAll('.feedback-btn').forEach(b => b.disabled = false);
            return;
        }

        if (bar) {
            bar.innerHTML = `
                <span class="feedback-thanks">
                    ${vote === 'correct' ? '✅ Thanks! Marked as correct.' : '🔄 Thanks! Flagged for retraining.'}
                </span>
            `;
        }

        showToast(
            vote === 'correct'
                ? '👍 Feedback saved'
                : '👎 Flagged as incorrect — will improve the model'
        );

    } catch {
        showToast('Could not save feedback');
        if (bar) bar.querySelectorAll('.feedback-btn').forEach(b => b.disabled = false);
    }
}


function renderHistoryFeedback(scan) {

    if (scan.feedback) {
        const label = scan.feedback === 'correct' ? '✅ Marked correct' : '🔄 Flagged for retraining';
        return `
            <div class="feedback-bar feedback-bar--inline">
                <span class="feedback-thanks">${label}</span>
            </div>
        `;
    }

    return `
        <div class="feedback-bar feedback-bar--inline">
            <span class="feedback-label">Was this accurate?</span>
            <div class="feedback-btns">
                <button class="feedback-btn thumb-up"
                    onclick="submitHistoryFeedback(${scan.id}, 'correct', this)">👍</button>
                <button class="feedback-btn thumb-down"
                    onclick="submitHistoryFeedback(${scan.id}, 'wrong', this)">👎</button>
            </div>
        </div>
    `;
}


async function submitHistoryFeedback(scanId, vote, triggerBtn) {

    const bar = triggerBtn.closest('.feedback-bar');
    if (bar) bar.querySelectorAll('.feedback-btn').forEach(b => b.disabled = true);

    try {
        const res = await fetch(`${API_BASE}/api/feedback/${scanId}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ vote })
        });

        const data = await res.json();

        if (!res.ok) {
            showToast(data.error || 'Feedback failed');
            if (bar) bar.querySelectorAll('.feedback-btn').forEach(b => b.disabled = false);
            return;
        }

        if (bar) {
            bar.innerHTML = `
                <span class="feedback-thanks">
                    ${vote === 'correct' ? '✅ Marked correct' : '🔄 Flagged for retraining'}
                </span>
            `;
        }

        showToast('Feedback saved');

    } catch {
        showToast('Could not save feedback');
        if (bar) bar.querySelectorAll('.feedback-btn').forEach(b => b.disabled = false);
    }
}


/* ════════════════════════════════════════
   SCAN MODE SWITCHING
════════════════════════════════════════ */

function switchScanMode(mode, btn) {

    document.querySelectorAll('.stab').forEach(b => b.classList.remove('active'));
    if (btn) btn.classList.add('active');

    document.querySelectorAll('.scan-mode').forEach(m => m.style.display = 'none');
    const target = document.getElementById('mode-' + mode);
    if (target) target.style.display = 'block';
}


/* ════════════════════════════════════════
   PASTE FROM CLIPBOARD
════════════════════════════════════════ */

async function pasteFromClipboard() {
    try {
        const text = await navigator.clipboard.readText();
        const el = document.getElementById('urlInput');
        if (el) el.value = text;
    } catch {
        showToast('Clipboard permission denied');
    }
}


/* ════════════════════════════════════════
   BULK SCAN
════════════════════════════════════════ */

async function analyzeBulk() {

    const raw  = (document.getElementById('bulkInput') || {}).value || '';
    const urls = raw.split(/\n/).map(u => u.trim()).filter(Boolean);

    if (!urls.length) { showToast('Enter at least one URL'); return; }

    showScanOverlay(true);

    const results = [];

    for (const url of urls) {
        try {
            const res = await fetch(`${API_BASE}/api/analyze/url`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url })
            });
            const data = await res.json();
            results.push({ url, ...data });
            updateDashboard(data);
        } catch {
            results.push({ url, error: true });
        }
    }

    showScanOverlay(false);

    const box = document.getElementById('bulkResults');
    if (!box) return;

    box.innerHTML = results.map(r => `
        <div class="bulk-row bulk-${(r.risk_level || 'low').toLowerCase()}">
            <span class="bulk-url">${r.url}</span>
            <span class="bulk-badge">${r.risk_level || 'ERROR'}</span>
            <span class="bulk-pct">${r.fraud_probability ? Math.round(r.fraud_probability * 100) + '%' : '—'}</span>
        </div>
    `).join('');
}


/* ════════════════════════════════════════
   QR CODE SCAN
════════════════════════════════════════ */

function initQrZone() {

    const zone  = document.getElementById('qrDropZone');
    const input = document.getElementById('qrFileInput');
    if (!zone || !input) return;

    zone.addEventListener('click',     () => input.click());
    input.addEventListener('change',   () => { if (input.files?.[0]) uploadQr(input.files[0]); });
    zone.addEventListener('dragover',  e  => { e.preventDefault(); zone.classList.add('drag-over'); });
    zone.addEventListener('dragleave', ()  => zone.classList.remove('drag-over'));
    zone.addEventListener('drop',      e  => {
        e.preventDefault();
        zone.classList.remove('drag-over');
        const file = e.dataTransfer.files[0];
        if (file) uploadQr(file);
    });
}

async function uploadQr(file) {

    if (!file.type.startsWith('image/')) {
        showToast('Please drop an image file');
        return;
    }

    const preview = document.getElementById('qrPreview');
    if (preview) {
        preview.src = URL.createObjectURL(file);
        preview.style.display = 'block';
    }

    showScanOverlay(true);

    const fd = new FormData();
    fd.append('file', file);

    try {
        const res  = await fetch(`${API_BASE}/api/analyze/qr`, { method: 'POST', body: fd });
        const data = await res.json();
        showScanOverlay(false);
        if (data.error) { showToast('QR Error: ' + data.error); return; }
        updateDashboard(data);
    } catch {
        showScanOverlay(false);
        showToast('Could not connect to backend');
    }
}


/* ════════════════════════════════════════
   SPOT THE PHISH — Game Engine
════════════════════════════════════════ */

const GAME_URLS = [
    // [url, isThreat, explanation]
    ['https://www.google.com/search?q=weather',            false, 'Legit Google search — HTTPS, no suspicious patterns.'],
    ['http://paypal-login-secure.xyz/update',              true,  'Fake PayPal — HTTP only, hyphen in domain, .xyz TLD.'],
    ['https://github.com/user/repository',                 false, 'GitHub repo URL — trusted domain, HTTPS.'],
    ['http://192.168.1.1/admin/login.php',                 true,  'IP address as hostname is a classic phishing sign.'],
    ['https://amazon.com/dp/B09BHXFL3F',                   false, 'Standard Amazon product link.'],
    ['http://amaz0n-secure-login.com/account',             true,  'Letter swap (0 for o), hyphen, no HTTPS — textbook phish.'],
    ['https://docs.microsoft.com/en-us/azure/',            false, 'Official Microsoft docs subdomain.'],
    ['http://bit.ly/3xR9qAm',                              true,  'URL shortener hides the real destination — always suspicious.'],
    ['https://stackoverflow.com/questions/12345',          false, 'Stack Overflow question — safe.'],
    ['http://netflix-verify-account.tk/login',             true,  '.tk is a free TLD heavily abused by phishers.'],
    ['https://mail.google.com/mail/u/0/#inbox',            false, 'Gmail — legitimate Google subdomain.'],
    ['http://secure-bankofamerica-login.com',              true,  'Legitimate brands never hyphenate their domain like this.'],
    ['https://en.wikipedia.org/wiki/Phishing',             false, 'Wikipedia article — safe.'],
    ['http://update-your-paypal-info.net/verify',          true,  'Multiple phishing keywords + .net instead of .com.'],
    ['https://www.apple.com/iphone',                       false, "Apple's official website — HTTPS, no tricks."],
    ['http://apple-id-locked.support/unlock',              true,  'Fake Apple support — hyphenated, no HTTPS.'],
    ['https://twitter.com/NASA',                           false, 'Twitter/X NASA account — safe.'],
    ['http://twitterr.com/login',                          true,  'Double-r typosquat of Twitter.'],
    ['https://www.youtube.com/watch?v=dQw4w9WgXcQ',       false, 'YouTube video link — safe.'],
    ['http://you-tube-premium-free.xyz',                   true,  'Hyphenated fake, .xyz TLD, free premium scam.'],
    ['https://login.microsoft.com/common/oauth2',          false, 'Microsoft OAuth endpoint — legitimate subdomain.'],
    ['http://micros0ft-helpdesk.com/fix-virus',            true,  'Tech support scam URL — letter swap, no HTTPS.'],
    ['https://www.reddit.com/r/cybersecurity',             false, 'Reddit community page — safe.'],
    ['http://redd1t-promo-coins.com/claim',                true,  'Reddit typosquat with promo scam path.'],
    ['https://www.dropbox.com/sh/abc123',                  false, 'Dropbox share link — HTTPS, official domain.'],
];

let gameState = {
    score:      0,
    streak:     0,
    bestStreak: 0,
    correct:    0,
    qIndex:     0,
    questions:  [],
    timer:      null,
    timeLeft:   5,
    maxTime:    5,
    answered:   false,
    difficulty: 'medium',
    highScore:  parseInt(localStorage.getItem('phishGameHS') || '0'),
};

function setDifficulty(level, btn) {
    document.querySelectorAll('.diff-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    gameState.difficulty = level;
    gameState.maxTime    = { easy: 8, medium: 5, hard: 3 }[level];
}

function startGame() {

    const shuffled       = [...GAME_URLS].sort(() => Math.random() - 0.5);
    gameState.questions  = shuffled.slice(0, 10);
    gameState.score      = 0;
    gameState.streak     = 0;
    gameState.bestStreak = 0;
    gameState.correct    = 0;
    gameState.qIndex     = 0;
    gameState.answered   = false;
    gameState.maxTime    = { easy: 8, medium: 5, hard: 3 }[gameState.difficulty];

    document.getElementById('gameStart').style.display   = 'none';
    document.getElementById('gameOver').style.display    = 'none';
    document.getElementById('gamePlaying').style.display = 'block';
    document.getElementById('gameQTotal').textContent    = gameState.questions.length;

    updateHUD();
    loadQuestion();
}

function loadQuestion() {

    if (gameState.qIndex >= gameState.questions.length) return endGame();

    const [url, isThreat] = gameState.questions[gameState.qIndex];

    gameState.answered = false;
    gameState.timeLeft = gameState.maxTime;

    /* reset card */
    document.getElementById('gameUrlCard').className    = 'game-url-card';
    document.getElementById('gameUrlText').textContent  = url;
    document.getElementById('gameUrlBadge').textContent = '🔍 ASSESS';
    document.getElementById('gameUrlHint').textContent  = '';
    document.getElementById('gameFeedback').style.display    = 'none';
    document.getElementById('gameAnswerBtns').style.display  = 'flex';
    document.getElementById('gameQNum').textContent          = gameState.qIndex + 1;

    /* progress bar */
    const pct = (gameState.qIndex / gameState.questions.length) * 100;
    document.getElementById('gameProgress').style.width = pct + '%';

    startTimer();
}

function startTimer() {

    clearInterval(gameState.timer);

    const arc          = document.getElementById('timerArc');
    const circumference = 2 * Math.PI * 26;
    arc.style.strokeDasharray = circumference;

    gameState.timer = setInterval(() => {

        gameState.timeLeft -= 0.1;

        const ratio = Math.max(0, gameState.timeLeft / gameState.maxTime);
        arc.style.strokeDashoffset = circumference * (1 - ratio);

        document.getElementById('timerNum').textContent = Math.ceil(gameState.timeLeft);

        arc.style.stroke =
            gameState.timeLeft < 2                       ? '#ff3d5a'
          : gameState.timeLeft < gameState.maxTime * 0.5 ? '#ffb020'
          :                                                '#4f90ff';

        if (gameState.timeLeft <= 0) {
            clearInterval(gameState.timer);
            if (!gameState.answered) submitAnswer(null); // timeout
        }
    }, 100);
}

function submitAnswer(choice) {

    if (gameState.answered) return;
    gameState.answered = true;
    clearInterval(gameState.timer);

    const [, isThreat, explanation] = gameState.questions[gameState.qIndex];

    /* FIX: removed the dead/buggy `const correct` variable that was here.
       isCorrect is the single source of truth. */
    const isCorrect = choice !== null && (choice === 'threat') === isThreat;

    let points = 0;

    if (isCorrect) {
        const speedBonus = Math.round((gameState.timeLeft / gameState.maxTime) * 50);
        gameState.streak++;
        gameState.bestStreak = Math.max(gameState.bestStreak, gameState.streak);
        gameState.correct++;
        const multiplier = Math.min(gameState.streak, 5);
        points = (100 + speedBonus) * multiplier;
        gameState.score += points;
    } else {
        gameState.streak = 0;
    }

    updateHUD();

    /* visual card state */
    document.getElementById('gameUrlCard').className =
        'game-url-card ' + (isCorrect ? 'card-correct' : 'card-wrong');

    /* feedback panel */
    const fb = document.getElementById('gameFeedback');
    fb.style.display = 'flex';
    document.getElementById('gameAnswerBtns').style.display = 'none';

    const verdictEl = document.getElementById('feedbackVerdict');
    if (choice === null) {
        verdictEl.textContent = "⏱ Time's Up!";
        verdictEl.className   = 'feedback-verdict verdict-wrong';
    } else if (isCorrect) {
        verdictEl.textContent = '✅ Correct!';
        verdictEl.className   = 'feedback-verdict verdict-correct';
    } else {
        verdictEl.textContent = '❌ Wrong!';
        verdictEl.className   = 'feedback-verdict verdict-wrong';
    }

    document.getElementById('feedbackExplanation').textContent = explanation;
    document.getElementById('feedbackPoints').textContent =
        isCorrect
            ? `+${points} pts${gameState.streak > 1 ? ' 🔥 ×' + Math.min(gameState.streak, 5) : ''}`
            : '+0 pts';

    /* auto-advance */
    setTimeout(() => {
        gameState.qIndex++;
        loadQuestion();
    }, 2200);
}

function updateHUD() {
    document.getElementById('gameScore').textContent  = gameState.score;
    document.getElementById('gameStreak').textContent = gameState.streak;
}

function endGame() {

    clearInterval(gameState.timer);
    document.getElementById('gamePlaying').style.display = 'none';
    document.getElementById('gameOver').style.display    = 'block';

    if (gameState.score > gameState.highScore) {
        gameState.highScore = gameState.score;
        localStorage.setItem('phishGameHS', gameState.highScore);
    }

    document.getElementById('gameHighScore').textContent = gameState.highScore;
    document.getElementById('goScore').textContent       = gameState.score;
    document.getElementById('goCorrect').textContent     = gameState.correct + '/' + gameState.questions.length;
    document.getElementById('goBestStreak').textContent  = gameState.bestStreak;

    const pct = (gameState.correct / gameState.questions.length) * 100;
    let rank, icon;

    if      (pct === 100) { rank = "Perfect! You're a Phishing Hunter 🏆"; icon = '🏆'; }
    else if (pct >=  80)  { rank = 'Security Expert 🛡️';                   icon = '🛡️'; }
    else if (pct >=  60)  { rank = 'Cyber Analyst 🔍';                     icon = '🔍'; }
    else if (pct >=  40)  { rank = 'Needs Practice 📚';                    icon = '📚'; }
    else                  { rank = 'Easy Phishing Target 🎣';               icon = '🎣'; }

    document.getElementById('goIcon').textContent  = icon;
    document.getElementById('goTitle').textContent = rank;
    document.getElementById('goRank').textContent  =
        `${gameState.correct} correct out of ${gameState.questions.length}`;
}

function showGameMenu() {
    document.getElementById('gameOver').style.display    = 'none';
    document.getElementById('gameStart').style.display   = 'block';
    document.getElementById('gameHighScore').textContent = gameState.highScore;
}

function backToGameMenu() {

    const startScreen = document.getElementById('gameStart');
    const playingScreen = document.getElementById('gamePlaying');
    const gameOverScreen = document.getElementById('gameOver');

    if (startScreen) {
        startScreen.style.display = 'block';
    }

    if (playingScreen) {
        playingScreen.style.display = 'none';
    }

    if (gameOverScreen) {
        gameOverScreen.style.display = 'none';
    }
}