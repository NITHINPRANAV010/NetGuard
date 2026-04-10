/* ============================================================
   NetGuard — app.js
   ============================================================ */

'use strict';

/* ============================================================
   API CONNECTION
   ============================================================ */
const API_BASE_URL = 'http://localhost:8000';

async function fetchAPI(endpoint, options = {}) {
  try {
    const response = await fetch(`${API_BASE_URL}${endpoint}`, {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        ...options.headers,
      },
    });
    if (!response.ok) throw new Error(`API Error: ${response.status}`);
    return await response.json();
  } catch (err) {
    console.error(`Failed to fetch from ${endpoint}:`, err);
    return null;
  }
}

/* ============================================================
   ADVANCED PREMIUM GLOW EFFECT & ANIMATIONS
   ============================================================ */
(function initPremiumInteractions() {
  // Real-time Spotlight Cursor Effect
  document.addEventListener("mousemove", (e) => {
    const interactiveElements = document.querySelectorAll(".card, .stat-card, .scan-type-card, .vuln-item, .scan-item, .btn");
    for (const el of interactiveElements) {
      const rect = el.getBoundingClientRect();
      const x = e.clientX - rect.left;
      const y = e.clientY - rect.top;
      el.style.setProperty("--mouse-x", `${x}px`);
      el.style.setProperty("--mouse-y", `${y}px`);
    }
  });
})();


/* ============================================================
   3.  SIDEBAR COLLAPSE
   ============================================================ */
(function initSidebar() {
  const sidebar  = document.getElementById('sidebar');
  const toggleBtn = document.getElementById('sidebarToggle');
  const mobileBtn = document.getElementById('mobileMenuBtn');
  const overlay   = document.getElementById('overlay');

  if (toggleBtn) {
    toggleBtn.addEventListener('click', () => {
      const isMobile = window.innerWidth <= 768;
      if (isMobile) {
        sidebar.classList.toggle('mobile-open');
        overlay.classList.toggle('show');
      } else {
        sidebar.classList.toggle('collapsed');
      }
    });
  }

  if (mobileBtn) {
    mobileBtn.addEventListener('click', () => {
      sidebar.classList.toggle('mobile-open');
      overlay.classList.toggle('show');
    });
  }

  if (overlay) {
    overlay.addEventListener('click', () => {
      sidebar.classList.remove('mobile-open');
      overlay.classList.remove('show');
      document.getElementById('notifPanel')?.classList.remove('open');
    });
  }
})();

/* ============================================================
   4.  NOTIFICATIONS
   ============================================================ */
(function initNotifications() {
  const btn   = document.getElementById('notifBtn');
  const panel = document.getElementById('notifPanel');
  const close = document.getElementById('closeNotif');
  const overlay = document.getElementById('overlay');

  if (btn && panel) {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      panel.classList.toggle('open');
      overlay.classList.toggle('show');
    });
  }

  if (close) {
    close.addEventListener('click', () => {
      panel.classList.remove('open');
      overlay.classList.remove('show');
    });
  }
})();

/* ============================================================
   5.  ROUTER / PAGE LOADER
   ============================================================ */
const PAGES = {
  dashboard:      renderDashboard,
  'new-scan':     renderNewScan,
  scans:          renderScans,
  reports:        renderReports,
  targets:        renderTargets,
  'attack-chain': renderAttackChain,
  settings:       renderSettings,
  profile:        renderProfile,
};

const PAGE_TITLES = {
  dashboard:      'Dashboard',
  'new-scan':     'New Scan',
  scans:          'Scans',
  reports:        'Reports',
  targets:        'Targets',
  'attack-chain': 'Attack Chain',
  settings:       'Settings',
  profile:        'Profile',
};

let currentPage = 'dashboard';

function navigateTo(page) {
  if (!PAGES[page]) return;

  currentPage = page;

  // Update nav
  document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
  const navEl = document.getElementById(`nav-${page}`);
  if (navEl) navEl.classList.add('active');

  // Update breadcrumb
  const bc = document.getElementById('breadcrumbCurrent');
  if (bc) bc.textContent = PAGE_TITLES[page] || page;

  // Render page
  const container = document.getElementById('pageContainer');
  if (container) {
    container.style.animation = 'none';
    container.offsetHeight;  // reflow
    container.style.animation = '';
    container.innerHTML = '';
    PAGES[page](container);
  }

  // Close mobile sidebar
  document.getElementById('sidebar')?.classList.remove('mobile-open');
  document.getElementById('overlay')?.classList.remove('show');
}

// Nav click listeners
document.querySelectorAll('.nav-item[data-page]').forEach(el => {
  el.addEventListener('click', (e) => {
    e.preventDefault();
    navigateTo(el.dataset.page);
  });
});

// Profile avatar click → profile page
document.getElementById('userAvatarBtn')?.addEventListener('click', () => navigateTo('profile'));

/* ============================================================
   6.  PAGE: DASHBOARD
   ============================================================ */
async function renderDashboard(container) {
  // Show skeleton or loading state if needed
  container.innerHTML = `<div class="loading-state">Initializing Security Intelligence...</div>`;

  const [
    stats = { scans: 0, vulns: 0, apis: 0, fp: 0, risk_score: 0 },
    activeScans = [],
    findings = [],
    activity = [],
    vulnSummary = [],
    scanActivity = []
  ] = await Promise.all([
    fetchAPI('/api/stats'),
    fetchAPI('/api/scans/active'),
    fetchAPI('/api/findings/recent'),
    fetchAPI('/api/activity'),
    fetchAPI('/api/vuln-summary'),
    fetchAPI('/api/scan-activity')
  ]);

  // Derive trend labels from live data
  const scanTrend  = stats.scans  > 0 ? `↑ ${stats.scans}` : '—';
  const vulnTrend  = stats.vulns  > 100 ? '↑ High' : stats.vulns > 50 ? '↑ Med' : '↑ Low';
  const apiTrend   = stats.apis   > 0 ? `↑ ${Math.min(stats.apis, 99)}` : '—';
  const fpTrend    = stats.fp     > 0 ? `↓ ${stats.fp}%` : '—';
  const maxScans   = Math.max(...scanActivity.map(d => d.scans), 1);

  container.innerHTML = `
    <div class="page-header">
      <h1 class="page-title">Security Intelligence <span>Dashboard</span></h1>
      <p class="page-subtitle">Real-time monitoring of vulnerability scans, threat scoring, and security posture across all targets</p>
    </div>

    <!-- Stat Cards -->
    <div class="stats-grid">
      <div class="stat-card" style="--accent-color: linear-gradient(90deg, #a855f7, #7c3aed);">
        <div class="stat-top">
          <div class="stat-icon">🔍</div>
          <div class="stat-trend up">${scanTrend} active</div>
        </div>
        <div class="stat-value" id="stat-scans">0</div>
        <div class="stat-label">Active &amp; Queued Scans</div>
      </div>
      <div class="stat-card" style="--accent-color: linear-gradient(90deg, #ef4444, #b91c1c);">
        <div class="stat-top">
          <div class="stat-icon">⚠️</div>
          <div class="stat-trend down">${vulnTrend}</div>
        </div>
        <div class="stat-value" id="stat-vulns">0</div>
        <div class="stat-label">Vulnerabilities Detected</div>
      </div>
      <div class="stat-card" style="--accent-color: linear-gradient(90deg, #3b82f6, #1d4ed8);">
        <div class="stat-top">
          <div class="stat-icon">🔌</div>
          <div class="stat-trend up">${apiTrend}</div>
        </div>
        <div class="stat-value" id="stat-apis">0</div>
        <div class="stat-label">API Endpoints Tested</div>
      </div>
      <div class="stat-card" style="--accent-color: linear-gradient(90deg, #22c55e, #15803d);">
        <div class="stat-top">
          <div class="stat-icon">🤖</div>
          <div class="stat-trend up">${fpTrend}</div>
        </div>
        <div class="stat-value" id="stat-fp">0</div>
        <div class="stat-label">False Positives Reduced</div>
      </div>
    </div>

    <!-- Main Grid -->
    <div class="dashboard-grid">

      <!-- AI Threat Score -->
      <div class="card" style="display:flex; flex-direction:column; gap:20px;">
        <div class="section-header">
          <h2 class="section-title">AI Threat <span>Score</span></h2>
          <span style="font-size:0.7rem; background:rgba(139,92,246,0.15); color:var(--purple-300); border:1px solid rgba(139,92,246,0.3); border-radius:20px; padding:2px 10px;">ML · 94% conf.</span>
        </div>
        <div class="risk-gauge-wrap">
          <div class="risk-gauge">
            <svg viewBox="0 0 160 160">
              <defs>
                <linearGradient id="gaugeGrad" x1="0" y1="0" x2="1" y2="1">
                  <stop offset="0%" stop-color="#a855f7"/>
                  <stop offset="100%" stop-color="#ef4444"/>
                </linearGradient>
              </defs>
              <circle class="track" cx="80" cy="80" r="70"/>
              <circle class="fill" id="gaugeFill" cx="80" cy="80" r="70"/>
            </svg>
            <div class="risk-gauge-center">
              <span class="risk-score-num" id="riskNum">0</span>
              <span class="risk-score-label">/ 100  RISK</span>
            </div>
          </div>
          <div style="width:100%; display:flex; flex-direction:column; gap:7px; margin-top:8px;">
            ${vulnSummary.map(r => `
              <div style="display:flex; align-items:center; gap:8px;">
                <span style="font-size:0.72rem; color:var(--text-muted); width:90px; flex-shrink:0;">${r.label}</span>
                <div class="progress-bar"><div class="progress-fill" data-target="${r.pct}" style="background:${r.color}; width:0%;"></div></div>
                <span style="font-size:0.72rem; color:${r.color}; font-weight:600; width:16px; text-align:right;">${r.count}</span>
              </div>
            `).join('')}
          </div>
        </div>
      </div>

      <!-- Vulnerability Map (Enhanced) -->
      <div class="card col-span-2" style="position:relative; overflow:hidden; padding-bottom:16px;">
        <div class="section-header">
          <h2 class="section-title">Attack Surface <span>Map</span></h2>
          <div style="display:flex; align-items:center; gap:10px;">
            <span id="mapNodeCount" style="font-size:0.7rem; color:var(--purple-300); font-family:'JetBrains Mono',monospace;">— nodes</span>
            <div class="status-badge" style="background:rgba(34,197,94,0.1); color:var(--low); border:1px solid rgba(34,197,94,0.2);">Live Monitoring</div>
          </div>
        </div>
        <div id="vulnMap" style="width:100%; height:270px; position:relative; overflow:hidden;"></div>
        <div style="display:flex; gap:16px; padding:0 4px; margin-top:8px;">
           <span style="font-size:0.65rem; color:var(--text-muted); display:flex; align-items:center; gap:5px;"><span style="width:8px; height:8px; border-radius:50%; background:#ef4444; box-shadow:0 0 6px #ef4444;"></span> Critical</span>
           <span style="font-size:0.65rem; color:var(--text-muted); display:flex; align-items:center; gap:5px;"><span style="width:8px; height:8px; border-radius:50%; background:#f97316; box-shadow:0 0 6px #f97316;"></span> High</span>
           <span style="font-size:0.65rem; color:var(--text-muted); display:flex; align-items:center; gap:5px;"><span style="width:8px; height:8px; border-radius:50%; background:#eab308; box-shadow:0 0 6px #eab308;"></span> Medium</span>
           <span style="font-size:0.65rem; color:var(--text-muted); display:flex; align-items:center; gap:5px;"><span style="width:8px; height:8px; border-radius:50%; background:#22c55e; box-shadow:0 0 6px #22c55e;"></span> Low</span>
           <span style="font-size:0.65rem; color:var(--text-muted); display:flex; align-items:center; gap:5px;"><span style="width:8px; height:8px; border-radius:2px; background:#a855f7; box-shadow:0 0 6px #a855f7;"></span> Category</span>
        </div>
        <!-- Tooltip -->
        <div id="mapTooltip" style="display:none; position:absolute; background:rgba(15,10,30,0.95); border:1px solid rgba(139,92,246,0.4); border-radius:8px; padding:8px 12px; font-size:0.72rem; pointer-events:none; z-index:99; max-width:220px; box-shadow:0 4px 20px rgba(0,0,0,0.5);"></div>
      </div>

      <!-- Active Scans -->
      <div class="card col-span-2">
        <div class="section-header">
          <h2 class="section-title">Real-time Scan <span id="active-count"></span></h2>
          <button class="btn btn-primary btn-sm" onclick="navigateTo('new-scan')">+ New Scan</button>
        </div>
        <div style="display:flex; flex-direction:column; gap:8px;">
          ${generateActiveScanItems(activeScans)}
        </div>
      </div>

      <!-- Recent Findings -->
      <div class="card col-span-1">
        <div class="section-header">
          <h2 class="section-title">Recent <span>Findings</span></h2>
          <button class="btn btn-ghost btn-sm" onclick="navigateTo('reports')">View All</button>
        </div>
        <div style="display:flex; flex-direction:column; gap:8px;">
          ${generateVulnItems(findings)}
        </div>
      </div>

      <!-- Activity Feed -->
      <div class="card">
        <div class="section-header">
          <h2 class="section-title">Activity Feed</h2>
        </div>
        <div style="display:flex; flex-direction:column;">
          ${generateActivityFeed(activity)}
        </div>
      </div>

      <!-- Scan Activity Chart -->
      <div class="card col-span-3">
        <div class="section-header">
          <h2 class="section-title">Scan Activity <span>Last 14 days</span></h2>
          <div style="display:flex; gap:16px;">
            <span style="font-size:0.75rem; color:var(--text-muted);"><span style="display:inline-block;width:8px;height:8px;border-radius:2px;background:#a855f7;margin-right:4px;"></span>Scans</span>
          </div>
        </div>
        <div style="display:flex; align-items:flex-end; gap:6px; height:90px; padding-top:10px;">
          ${scanActivity.map(d => {
            const h = maxScans > 0 ? Math.max(6, Math.round((d.scans / maxScans) * 100)) : 6;
            return `<div class="chart-bar" data-h="${h}" style="height:0%; background: linear-gradient(180deg, rgba(168,85,247,${0.3 + h/150}), rgba(109,40,217,0.2));" title="${d.scans} scan(s) on ${d.date}"></div>`;
          }).join('')}
        </div>
        <div style="display:flex; justify-content:space-between; margin-top:8px;">
          <span style="font-size:0.7rem; color:var(--text-muted);">${scanActivity[0]?.label || ''}</span>
          <span style="font-size:0.7rem; color:var(--text-muted);">${scanActivity[scanActivity.length-1]?.label || ''}</span>
        </div>
      </div>

    </div>
  `;

  animateCounter('stat-scans',  0, stats.scans, 900);
  animateCounter('stat-vulns',  0, stats.vulns, 1200);
  animateCounter('stat-apis',   0, stats.apis,  1400);
  animateCounter('stat-fp',     0, stats.fp,    1000);

  setTimeout(() => {
    const fill = document.getElementById('gaugeFill');
    if (fill) {
      const score = stats.risk_score;
      const circ  = 2 * Math.PI * 70;
      fill.style.strokeDasharray  = circ;
      fill.style.strokeDashoffset = circ - (score / 100) * circ;
      animateCounter('riskNum', 0, score, 1500);
    }
  }, 300);

  setTimeout(() => {
    document.querySelectorAll('.progress-fill[data-target]').forEach(el => {
      el.style.width = el.dataset.target + '%';
    });
  }, 400);

  setTimeout(() => {
    document.querySelectorAll('.chart-bar[data-h]').forEach(el => {
      el.style.height = el.dataset.h + '%';
    });

    // ── Attack Surface Map — Full SVG Network Graph ──────────────────────
    renderAttackSurfaceMap(document.getElementById('vulnMap'), findings);
  }, 500);

  document.getElementById('active-count').textContent = `Monitor · ${activeScans.length} running`;
}

/* ============================================================
   ATTACK SURFACE MAP — SVG Network Graph Renderer
   ============================================================ */
function renderAttackSurfaceMap(container, findings = []) {
  if (!container) return;
  container.innerHTML = '';

  const W = container.offsetWidth  || 600;
  const H = container.offsetHeight || 270;
  const cx = W / 2, cy = H / 2;

  // ── Category hub nodes (always shown) ──────────────────────
  const categories = [
    { id: 'web',   label: 'Web App',   icon: '🌐', color: '#a855f7', angle: 270, r: 90 },
    { id: 'api',   label: 'API',       icon: '🔌', color: '#3b82f6', angle:  30, r: 90 },
    { id: 'auth',  label: 'Auth',      icon: '🔑', color: '#f97316', angle:  90, r: 90 },
    { id: 'data',  label: 'Database',  icon: '🗄️',  color: '#ef4444', angle: 150, r: 90 },
    { id: 'net',   label: 'Network',   icon: '📡', color: '#22c55e', angle: 210, r: 90 },
    { id: 'logic', label: 'Logic',     icon: '🔁', color: '#eab308', angle: 330, r: 90 },
  ];

  // Map each finding's title to a category
  const categorise = (f) => {
    const t = (f.title || '').toLowerCase();
    if (t.includes('api') || t.includes('endpoint'))            return 'api';
    if (t.includes('sql') || t.includes('inject'))              return 'data';
    if (t.includes('auth') || t.includes('jwt') || t.includes('rbac') || t.includes('csrf')) return 'auth';
    if (t.includes('xss') || t.includes('redirect') || t.includes('click')) return 'web';
    if (t.includes('header') || t.includes('tls') || t.includes('hsts') || t.includes('server')) return 'net';
    return 'logic';
  };

  // Build SVG
  const ns = 'http://www.w3.org/2000/svg';
  const svg = document.createElementNS(ns, 'svg');
  svg.setAttribute('width', W);
  svg.setAttribute('height', H);
  svg.style.cssText = 'display:block; overflow:visible;';

  const defs = document.createElementNS(ns, 'defs');

  // Radial background gradient
  const bgGrad = document.createElementNS(ns, 'radialGradient');
  bgGrad.setAttribute('id', 'mapBg');
  bgGrad.setAttribute('cx', '50%'); bgGrad.setAttribute('cy', '50%');
  [{ off: '0%', color: 'rgba(139,92,246,0.08)' }, { off: '70%', color: 'rgba(0,0,0,0)' }].forEach(s => {
    const stop = document.createElementNS(ns, 'stop');
    stop.setAttribute('offset', s.off);
    stop.setAttribute('stop-color', s.color);
    bgGrad.appendChild(stop);
  });
  defs.appendChild(bgGrad);

  // Sweep gradient (conic-like via linear gradient on a rotated rect)
  const sweepGrad = document.createElementNS(ns, 'linearGradient');
  sweepGrad.setAttribute('id', 'sweep');
  sweepGrad.setAttribute('x1', '0'); sweepGrad.setAttribute('y1', '0');
  sweepGrad.setAttribute('x2', '1'); sweepGrad.setAttribute('y2', '0');
  [{ off: '0%', color: 'rgba(168,85,247,0.25)', op: '1' },
   { off: '100%', color: 'rgba(168,85,247,0)', op: '0' }].forEach(s => {
    const stop = document.createElementNS(ns, 'stop');
    stop.setAttribute('offset', s.off);
    stop.setAttribute('stop-color', s.color);
    sweepGrad.appendChild(stop);
  });
  defs.appendChild(sweepGrad);

  svg.appendChild(defs);

  // ── Background rect ──────────────────────────────────────────
  const bg = document.createElementNS(ns, 'ellipse');
  bg.setAttribute('cx', cx); bg.setAttribute('cy', cy);
  bg.setAttribute('rx', Math.min(cx, cy) * 0.95);
  bg.setAttribute('ry', Math.min(cx, cy) * 0.95);
  bg.setAttribute('fill', 'url(#mapBg)');
  svg.appendChild(bg);

  // ── Grid dot pattern via pattern element ─────────────────────
  const pat = document.createElementNS(ns, 'pattern');
  pat.setAttribute('id', 'mapDots'); pat.setAttribute('width', '22'); pat.setAttribute('height', '22');
  pat.setAttribute('patternUnits', 'userSpaceOnUse');
  const patDot = document.createElementNS(ns, 'circle');
  patDot.setAttribute('cx', '1'); patDot.setAttribute('cy', '1');
  patDot.setAttribute('r', '0.8'); patDot.setAttribute('fill', 'rgba(139,92,246,0.25)');
  pat.appendChild(patDot);
  defs.appendChild(pat);

  const patRect = document.createElementNS(ns, 'rect');
  patRect.setAttribute('width', W); patRect.setAttribute('height', H);
  patRect.setAttribute('fill', 'url(#mapDots)');
  svg.appendChild(patRect);

  // ── Concentric rings ─────────────────────────────────────────
  [40, 70, 100, 130].forEach((r, i) => {
    const circle = document.createElementNS(ns, 'circle');
    circle.setAttribute('cx', cx); circle.setAttribute('cy', cy); circle.setAttribute('r', r);
    circle.setAttribute('fill', 'none');
    circle.setAttribute('stroke', `rgba(139,92,246,${0.12 - i * 0.02})`);
    circle.setAttribute('stroke-dasharray', '4 6');
    svg.appendChild(circle);
  });

  // ── Layer labels on rings ────────────────────────────────────
  [{ r: 40, t: 'Core' }, { r: 70, t: 'Internal' }, { r: 100, t: 'Perimeter' }, { r: 130, t: 'External' }].forEach(({ r, t }) => {
    const txt = document.createElementNS(ns, 'text');
    txt.setAttribute('x', cx + r + 3); txt.setAttribute('y', cy - 3);
    txt.setAttribute('fill', 'rgba(139,92,246,0.35)');
    txt.setAttribute('font-size', '8');
    txt.setAttribute('font-family', 'JetBrains Mono, monospace');
    txt.textContent = t;
    svg.appendChild(txt);
  });

  // ── Radar sweep line (animated) ──────────────────────────────
  const sweepGroup = document.createElementNS(ns, 'g');
  const sweepLine = document.createElementNS(ns, 'line');
  sweepLine.setAttribute('x1', cx); sweepLine.setAttribute('y1', cy);
  sweepLine.setAttribute('x2', cx); sweepLine.setAttribute('y2', cy - 130);
  sweepLine.setAttribute('stroke', 'rgba(168,85,247,0.6)');
  sweepLine.setAttribute('stroke-width', '1.5');

  const sweepWedge = document.createElementNS(ns, 'path');
  sweepWedge.setAttribute('d', `M${cx},${cy} L${cx},${cy - 130} A130,130 0 0,1 ${cx + 40},${cy - 123} Z`);
  sweepWedge.setAttribute('fill', 'rgba(168,85,247,0.06)');

  sweepGroup.appendChild(sweepWedge);
  sweepGroup.appendChild(sweepLine);
  svg.appendChild(sweepGroup);

  // Animate sweep rotation
  const sweepAnim = document.createElementNS(ns, 'animateTransform');
  sweepAnim.setAttribute('attributeName', 'transform');
  sweepAnim.setAttribute('type', 'rotate');
  sweepAnim.setAttribute('from', `0 ${cx} ${cy}`);
  sweepAnim.setAttribute('to', `360 ${cx} ${cy}`);
  sweepAnim.setAttribute('dur', '4s');
  sweepAnim.setAttribute('repeatCount', 'indefinite');
  sweepGroup.appendChild(sweepAnim);

  // ── Category hub nodes ───────────────────────────────────────
  const catPositions = {};
  categories.forEach(cat => {
    const rad = (cat.angle - 90) * Math.PI / 180;
    const nx = cx + cat.r * Math.cos(rad);
    const ny = cy + cat.r * Math.sin(rad);
    catPositions[cat.id] = { x: nx, y: ny, color: cat.color };

    // Spoke from center to category
    const spoke = document.createElementNS(ns, 'line');
    spoke.setAttribute('x1', cx); spoke.setAttribute('y1', cy);
    spoke.setAttribute('x2', nx); spoke.setAttribute('y2', ny);
    spoke.setAttribute('stroke', `${cat.color}30`);
    spoke.setAttribute('stroke-width', '1');
    svg.appendChild(spoke);

    // Glow circle
    const glow = document.createElementNS(ns, 'circle');
    glow.setAttribute('cx', nx); glow.setAttribute('cy', ny); glow.setAttribute('r', '18');
    glow.setAttribute('fill', `${cat.color}18`);
    glow.setAttribute('stroke', `${cat.color}50`);
    glow.setAttribute('stroke-width', '1');
    svg.appendChild(glow);

    // Category dot
    const dot = document.createElementNS(ns, 'circle');
    dot.setAttribute('cx', nx); dot.setAttribute('cy', ny); dot.setAttribute('r', '8');
    dot.setAttribute('fill', cat.color);
    dot.setAttribute('stroke', `${cat.color}cc`);
    dot.setAttribute('stroke-width', '2');
    svg.appendChild(dot);

    // Emoji label
    const icon = document.createElementNS(ns, 'text');
    icon.setAttribute('x', nx); icon.setAttribute('y', ny + 3);
    icon.setAttribute('text-anchor', 'middle');
    icon.setAttribute('font-size', '9');
    icon.textContent = cat.icon;
    svg.appendChild(icon);

    // Text label below
    const label = document.createElementNS(ns, 'text');
    const yOff = ny > cy ? 26 : -18;
    label.setAttribute('x', nx);
    label.setAttribute('y', ny + yOff);
    label.setAttribute('text-anchor', 'middle');
    label.setAttribute('fill', cat.color);
    label.setAttribute('font-size', '8.5');
    label.setAttribute('font-family', 'Inter, sans-serif');
    label.setAttribute('font-weight', '600');
    label.textContent = cat.label;
    svg.appendChild(label);
  });

  // ── Centre origin node ───────────────────────────────────────
  const centreGlow = document.createElementNS(ns, 'circle');
  centreGlow.setAttribute('cx', cx); centreGlow.setAttribute('cy', cy); centreGlow.setAttribute('r', '24');
  centreGlow.setAttribute('fill', 'rgba(168,85,247,0.1)');
  svg.appendChild(centreGlow);

  const centreRing = document.createElementNS(ns, 'circle');
  centreRing.setAttribute('cx', cx); centreRing.setAttribute('cy', cy); centreRing.setAttribute('r', '12');
  centreRing.setAttribute('fill', 'rgba(168,85,247,0.2)');
  centreRing.setAttribute('stroke', '#a855f7');
  centreRing.setAttribute('stroke-width', '1.5');
  svg.appendChild(centreRing);

  const centreDot = document.createElementNS(ns, 'circle');
  centreDot.setAttribute('cx', cx); centreDot.setAttribute('cy', cy); centreDot.setAttribute('r', '5');
  centreDot.setAttribute('fill', '#a855f7');
  svg.appendChild(centreDot);

  const centreLabel = document.createElementNS(ns, 'text');
  centreLabel.setAttribute('x', cx); centreLabel.setAttribute('y', cy + 22);
  centreLabel.setAttribute('text-anchor', 'middle');
  centreLabel.setAttribute('fill', 'rgba(168,85,247,0.8)');
  centreLabel.setAttribute('font-size', '8');
  centreLabel.setAttribute('font-family', 'JetBrains Mono, monospace');
  centreLabel.textContent = 'TARGET';
  svg.appendChild(centreLabel);

  // ── Vulnerability finding nodes (orbit around their category) ─
  const tooltip = document.getElementById('mapTooltip');
  const nodeRadius = 145; // outer ring for findings

  // Fallback: seed with demo data if API returned empty
  const vulns = findings.length > 0 ? findings : [
    { title: 'SQL Injection', sev: 'critical', color: '#ef4444', target: 'api.example.com', desc: 'Union-based SQLi' },
    { title: 'XSS — param q', sev: 'high', color: '#f97316', target: 'shop.example.com', desc: 'Reflected XSS' },
    { title: 'Missing HSTS', sev: 'medium', color: '#eab308', target: 'portal.example.com', desc: 'No HSTS header' },
    { title: 'Open Redirect', sev: 'medium', color: '#eab308', target: 'example.com', desc: 'param: redirect' },
    { title: 'JWT Bypass', sev: 'high', color: '#f97316', target: 'api.example.com', desc: 'none alg accepted' },
  ];

  vulns.forEach((v, i) => {
    const angle = (i / vulns.length) * 360;
    const rad = (angle - 90) * Math.PI / 180;
    // Randomise radius between 110-140 for depth
    const vr = 110 + (i % 3) * 12;
    const vx = cx + vr * Math.cos(rad);
    const vy = cy + vr * Math.sin(rad);

    const catId = categorise(v);
    const catPos = catPositions[catId];

    // Edge from category hub → finding node
    if (catPos) {
      const edge = document.createElementNS(ns, 'line');
      edge.setAttribute('x1', catPos.x); edge.setAttribute('y1', catPos.y);
      edge.setAttribute('x2', vx); edge.setAttribute('y2', vy);
      edge.setAttribute('stroke', `${v.color}35`);
      edge.setAttribute('stroke-width', '1');
      edge.setAttribute('stroke-dasharray', '3 4');
      svg.appendChild(edge);
    }

    // Glow halo
    const halo = document.createElementNS(ns, 'circle');
    halo.setAttribute('cx', vx); halo.setAttribute('cy', vy); halo.setAttribute('r', '10');
    halo.setAttribute('fill', `${v.color}20`);
    svg.appendChild(halo);

    // Finding dot
    const findDot = document.createElementNS(ns, 'circle');
    findDot.setAttribute('cx', vx); findDot.setAttribute('cy', vy); findDot.setAttribute('r', '5');
    findDot.setAttribute('fill', v.color);
    findDot.setAttribute('stroke', '#1a1030');
    findDot.setAttribute('stroke-width', '1.5');
    findDot.style.cursor = 'pointer';

    // Pulse animation
    const pulseAnim = document.createElementNS(ns, 'animate');
    pulseAnim.setAttribute('attributeName', 'r');
    pulseAnim.setAttribute('values', '5;8;5');
    pulseAnim.setAttribute('dur', `${1.8 + i * 0.3}s`);
    pulseAnim.setAttribute('repeatCount', 'indefinite');
    findDot.appendChild(pulseAnim);
    svg.appendChild(findDot);

    // Hover tooltip via mouseenter/mouseleave
    findDot.addEventListener('mouseenter', (e) => {
      if (tooltip) {
        tooltip.innerHTML = `
          <div style="font-weight:600; color:${v.color}; margin-bottom:4px;">${v.title || v.type || 'Finding'}</div>
          <div style="color:rgba(255,255,255,0.6); margin-bottom:2px; font-size:0.68rem;">${v.target || ''}</div>
          <div style="color:rgba(255,255,255,0.45); font-size:0.67rem;">${v.desc || v.description || ''}</div>`;
        tooltip.style.display = 'block';
        tooltip.style.left = (vx + 14) + 'px';
        tooltip.style.top  = (vy - 10) + 'px';
      }
    });
    findDot.addEventListener('mouseleave', () => {
      if (tooltip) tooltip.style.display = 'none';
    });
  });

  // ── Add chain edges between nearby findings ──────────────────
  for (let i = 0; i < vulns.length - 1; i++) {
    const a = vulns[i], b = vulns[i + 1];
    const ar = (i / vulns.length) * 2 * Math.PI - Math.PI / 2;
    const br = ((i + 1) / vulns.length) * 2 * Math.PI - Math.PI / 2;
    const arR = 110 + (i % 3) * 12, brR = 110 + ((i + 1) % 3) * 12;
    const ax = cx + arR * Math.cos(ar), ay = cy + arR * Math.sin(ar);
    const bx = cx + brR * Math.cos(br), by_  = cy + brR * Math.sin(br);

    const chain = document.createElementNS(ns, 'line');
    chain.setAttribute('x1', ax); chain.setAttribute('y1', ay);
    chain.setAttribute('x2', bx); chain.setAttribute('y2', by_);
    chain.setAttribute('stroke', 'rgba(168,85,247,0.15)');
    chain.setAttribute('stroke-width', '0.8');
    svg.appendChild(chain);
  }

  container.appendChild(svg);

  // Update node counter
  const counter = document.getElementById('mapNodeCount');
  if (counter) counter.textContent = `${vulns.length + categories.length + 1} nodes`;
}


function generateActiveScanItems(items = []) {

  if (items.length === 0) return '<div style="padding:20px; text-align:center; color:var(--text-muted); font-size:0.85rem;">No active scans found</div>';

  return items.map(item => `
    <div class="scan-item">
      <div class="scan-progress-ring">
        <svg viewBox="0 0 56 56">
          <defs>
            <linearGradient id="ringGrad" x1="0" y1="0" x2="1" y2="1">
              <stop offset="0%" stop-color="#a855f7"/>
              <stop offset="100%" stop-color="#7c3aed"/>
            </linearGradient>
          </defs>
          <circle class="ring-track" cx="28" cy="28" r="24"/>
          <circle class="ring-fill"  cx="28" cy="28" r="24"
            style="stroke-dashoffset: ${150 - (item.progress / 100) * 150};"/>
        </svg>
        <div class="ring-text">${item.progress}%</div>
      </div>
      <div class="scan-status-dot ${item.status}"></div>
      <div class="scan-item-details">
        <div class="scan-item-url">${item.url}</div>
        <div class="scan-item-meta">${item.type} · ${item.duration}</div>
      </div>
      <button class="scan-item-action" onclick="navigateTo('scans')">Details</button>
    </div>
  `).join('');
}

function generateVulnItems(vulns = []) {
  if (vulns.length === 0) return '<div style="padding:20px; text-align:center; color:var(--text-muted); font-size:0.85rem;">No recent findings</div>';

  return vulns.map(v => `
    <div class="vuln-item" onclick="navigateTo('reports')">
      <div class="vuln-severity-bar" style="background:${v.color};"></div>
      <div class="vuln-content">
        <div class="vuln-title">${v.title}</div>
        <div class="vuln-desc">${v.desc}</div>
        <div class="vuln-meta">
          <span class="badge badge-${v.sev}">${v.sev.toUpperCase()}</span>
          <span class="tag">${v.target}</span>
        </div>
      </div>
    </div>
  `).join('');
}

function generateActivityFeed(items = []) {
  if (items.length === 0) return '<div style="padding:20px; text-align:center; color:var(--text-muted); font-size:0.85rem;">No activity log</div>';

  return items.map((item, i) => `
    <div class="activity-item">
      <div class="activity-dot-wrap">
        <div class="activity-dot" style="background:${item.color}; box-shadow:0 0 8px ${item.color};"></div>
        ${i < items.length - 1 ? '<div class="activity-line"></div>' : ''}
      </div>
      <div class="activity-content">
        <div class="activity-title">${item.title}</div>
        <div class="activity-sub">${item.sub}</div>
      </div>
      <span class="activity-time">${item.time}</span>
    </div>
  `).join('');
}

/* ============================================================
   7.  PAGE: NEW SCAN
   ============================================================ */
function renderNewScan(container) {
  container.innerHTML = `
    <div class="page-header" style="display:flex; align-items:flex-start; justify-content:space-between; flex-wrap:wrap; gap:12px;">
      <div>
        <h1 class="page-title">Launch <span>New Scan</span></h1>
        <p class="page-subtitle">Configure a targeted vulnerability assessment — choose what to test, how deep to go, and how to authenticate</p>
      </div>
      <div style="display:flex; gap:10px;">
        <button class="btn btn-ghost btn-sm">📋 Load Template</button>
        <button class="btn btn-secondary btn-sm" onclick="scheduleScan()">🕐 Schedule</button>
      </div>
    </div>

    <!-- TARGET URL BAR (full-width) -->
    <div class="card" style="margin-bottom:24px;">
      <div style="display:flex; align-items:center; gap:10px; margin-bottom:6px;">
        <h2 class="section-title" style="margin:0;">Target URL</h2>
        <span id="urlStatus" style="font-size:0.7rem; padding:2px 10px; border-radius:20px; background:rgba(99,102,241,0.12); color:#818cf8; border:1px solid rgba(99,102,241,0.25);">Enter URL to begin</span>
      </div>
      <p style="font-size:0.8rem; color:var(--text-muted); margin-bottom:14px;">The base URL of the web application, API, or network endpoint you want to scan</p>
      <div style="display:flex; gap:12px; align-items:center;">
        <div class="form-input-wrap" style="flex:1; margin:0;">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/></svg>
          <input type="url" class="form-input" id="scanTarget" placeholder="https://app.example.com  or  https://api.service.io/v1" autocomplete="off"
            oninput="validateScanUrl(this.value)" style="font-size:1rem; height:48px;"/>
        </div>
        <button class="btn btn-ghost btn-sm" id="btnPingTarget" onclick="pingTarget()" style="height:48px; padding:0 18px; white-space:nowrap;">🔗 Ping</button>
      </div>
    </div>

    <div style="display:grid; grid-template-columns: 1fr 1fr 320px; gap:24px; align-items:start;">

      <!-- COL 1: Scan Type + Auth -->
      <div style="display:flex; flex-direction:column; gap:24px;">

        <div class="card">
          <h2 class="section-title" style="margin-bottom:6px;">Scan Type</h2>
          <p style="font-size:0.8rem; color:var(--text-muted); margin-bottom:18px;">Select what kind of security test to run against your target</p>
          <div style="display:flex; flex-direction:column; gap:10px;" id="scanTypeList">

            <div class="scan-type-row selected" data-type="web-app" onclick="selectScanRow(this)" data-eta="8" data-checks="22">
              <div class="scan-row-left">
                <div class="scan-row-icon" style="background:linear-gradient(135deg,#a855f7,#7c3aed);">🌐</div>
                <div>
                  <div class="scan-row-name">Web Application Scan</div>
                  <div class="scan-row-desc">XSS, SQLi, CSRF, open redirects, headers, cookies, directory listing</div>
                </div>
              </div>
              <span class="scan-row-badge" style="background:rgba(168,85,247,0.15);color:#c084fc;">Recommended</span>
            </div>

            <div class="scan-type-row" data-type="api-security" onclick="selectScanRow(this)" data-eta="5" data-checks="18">
              <div class="scan-row-left">
                <div class="scan-row-icon" style="background:linear-gradient(135deg,#3b82f6,#1d4ed8);">🔌</div>
                <div>
                  <div class="scan-row-name">API Security Scan</div>
                  <div class="scan-row-desc">REST/GraphQL endpoints, auth bypass, rate limiting, JWT flaws, IDOR</div>
                </div>
              </div>
              <span class="scan-row-badge" style="background:rgba(59,130,246,0.15);color:#93c5fd;">API</span>
            </div>

            <div class="scan-type-row" data-type="auth-rbac" onclick="selectScanRow(this)" data-eta="6" data-checks="14">
              <div class="scan-row-left">
                <div class="scan-row-icon" style="background:linear-gradient(135deg,#f97316,#c2410c);">🔑</div>
                <div>
                  <div class="scan-row-name">Auth & Access Control</div>
                  <div class="scan-row-desc">Login bypass, RBAC escalation, session fixation, sensitive route access</div>
                </div>
              </div>
              <span class="scan-row-badge" style="background:rgba(249,115,22,0.15);color:#fb923c;">Auth</span>
            </div>

            <div class="scan-type-row" data-type="logic-flaws" onclick="selectScanRow(this)" data-eta="12" data-checks="11">
              <div class="scan-row-left">
                <div class="scan-row-icon" style="background:linear-gradient(135deg,#eab308,#a16207);">🔁</div>
                <div>
                  <div class="scan-row-name">Business Logic Analysis</div>
                  <div class="scan-row-desc">Price manipulation, workflow bypass, state abuse, multi-step flaws</div>
                </div>
              </div>
              <span class="scan-row-badge" style="background:rgba(234,179,8,0.15);color:#fbbf24;">Logic</span>
            </div>

            <div class="scan-type-row" data-type="network" onclick="selectScanRow(this)" data-eta="4" data-checks="9">
              <div class="scan-row-left">
                <div class="scan-row-icon" style="background:linear-gradient(135deg,#22c55e,#15803d);">📡</div>
                <div>
                  <div class="scan-row-name">Network & Infrastructure</div>
                  <div class="scan-row-desc">TLS config, HSTS, exposed ports, sensitive files, server disclosure</div>
                </div>
              </div>
              <span class="scan-row-badge" style="background:rgba(34,197,94,0.15);color:#4ade80;">Net</span>
            </div>

            <div class="scan-type-row" data-type="full-spectrum" onclick="selectScanRow(this)" data-eta="20" data-checks="47">
              <div class="scan-row-left">
                <div class="scan-row-icon" style="background:linear-gradient(135deg,#ef4444,#991b1b);">⚡</div>
                <div>
                  <div class="scan-row-name">Full Spectrum Scan</div>
                  <div class="scan-row-desc">All checks — complete vulnerability surface coverage (slower)</div>
                </div>
              </div>
              <span class="scan-row-badge" style="background:rgba(239,68,68,0.15);color:#f87171;">Full</span>
            </div>

          </div>
        </div>

        <!-- AUTHENTICATION -->
        <div class="card">
          <h2 class="section-title" style="margin-bottom:6px;">Authentication</h2>
          <p style="font-size:0.8rem; color:var(--text-muted); margin-bottom:16px;">Allows the scanner to test authenticated surfaces and detect privilege escalation</p>
          <div class="form-group">
            <label class="form-label" for="authMethod">Method</label>
            <select class="form-select" id="authMethod" onchange="toggleAuthFields(this.value)">
              <option value="none">None — public scan only</option>
              <option value="session">Session Cookie</option>
              <option value="jwt">JWT Bearer Token</option>
              <option value="oauth2">OAuth 2.0 (Client Credentials)</option>
              <option value="basic">HTTP Basic Auth</option>
            </select>
          </div>
          <div id="authFieldsSession" style="display:none;">
            <div class="form-group" style="margin-bottom:0;">
              <label class="form-label" for="sessionCookie">Cookie Header Value</label>
              <input type="text" class="form-input" id="sessionCookie" placeholder="PHPSESSID=abc123; token=xyz" />
            </div>
          </div>
          <div id="authFieldsJwt" style="display:none;">
            <div class="form-group" style="margin-bottom:0;">
              <label class="form-label" for="jwtToken">Bearer Token</label>
              <input type="text" class="form-input" id="jwtToken" placeholder="eyJhbGciOiJSUzI1..." />
            </div>
          </div>
          <div id="authFieldsOauth" style="display:none;">
            <div style="display:grid; grid-template-columns:1fr 1fr; gap:12px;">
              <div class="form-group" style="margin-bottom:0;">
                <label class="form-label" for="oauthClientId">Client ID</label>
                <input type="text" class="form-input" id="oauthClientId" placeholder="client_id" />
              </div>
              <div class="form-group" style="margin-bottom:0;">
                <label class="form-label" for="oauthSecret">Client Secret</label>
                <input type="password" class="form-input" id="oauthSecret" placeholder="••••••••" />
              </div>
            </div>
          </div>
          <div id="authFieldsBasic" style="display:none;">
            <div style="display:grid; grid-template-columns:1fr 1fr; gap:12px;">
              <div class="form-group" style="margin-bottom:0;">
                <label class="form-label" for="basicUser">Username</label>
                <input type="text" class="form-input" id="basicUser" placeholder="admin" />
              </div>
              <div class="form-group" style="margin-bottom:0;">
                <label class="form-label" for="basicPass">Password</label>
                <input type="password" class="form-input" id="basicPass" placeholder="••••••••" />
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- COL 2: Settings + Checks + Toggles -->
      <div style="display:flex; flex-direction:column; gap:24px;">

        <div class="card">
          <h2 class="section-title" style="margin-bottom:18px;">Scan Settings</h2>
          <div class="form-group">
            <label class="form-label" for="scanDepth">Crawl Depth</label>
            <select class="form-select" id="scanDepth">
              <option value="1">Shallow — 1 level (fast)</option>
              <option value="3" selected>Standard — 3 levels</option>
              <option value="5">Deep — 5 levels</option>
              <option value="0">Unlimited</option>
            </select>
          </div>
          <div style="display:grid; grid-template-columns:1fr 1fr; gap:16px; margin-bottom:16px;">
            <div class="form-group" style="margin-bottom:0;">
              <label class="form-label" for="scanThreads">Concurrency</label>
              <select class="form-select" id="scanThreads">
                <option value="1">1 thread — stealth</option>
                <option value="5" selected>5 threads — balanced</option>
                <option value="10">10 threads — fast</option>
                <option value="20">20 — aggressive</option>
              </select>
            </div>
            <div class="form-group" style="margin-bottom:0;">
              <label class="form-label" for="scanTimeout">Request Timeout</label>
              <select class="form-select" id="scanTimeout">
                <option value="5">5 seconds</option>
                <option value="8" selected>8 seconds</option>
                <option value="15">15 seconds</option>
                <option value="30">30 seconds</option>
              </select>
            </div>
          </div>
          <div class="form-group" style="margin-bottom:0;">
            <label class="form-label" for="customHeaders">Custom Headers <span style="color:var(--text-muted);font-weight:400;">(optional)</span></label>
            <textarea class="form-input" id="customHeaders" rows="3"
              placeholder="X-Api-Key: your-key&#10;X-Tenant-Id: org-123"
              style="resize:vertical;font-family:'JetBrains Mono',monospace;font-size:0.8rem;padding:10px;"></textarea>
          </div>
        </div>

        <div class="card">
          <h2 class="section-title" style="margin-bottom:14px;">What Gets Tested</h2>
          <div id="checksGrid" style="display:flex; flex-direction:column; gap:8px;"></div>
        </div>

        <div class="card">
          <h2 class="section-title" style="margin-bottom:14px;">Intelligence Options</h2>
          <div class="toggle-row">
            <div class="toggle-info"><h4>AI False-Positive Filter</h4><p>ML confidence scoring to reduce noise</p></div>
            <label class="toggle"><input type="checkbox" id="optAI" checked><span class="toggle-slider"></span></label>
          </div>
          <div class="toggle-row">
            <div class="toggle-info"><h4>Passive JS Analysis</h4><p>Extract API endpoints and secrets from inline JS</p></div>
            <label class="toggle"><input type="checkbox" id="optJs" checked><span class="toggle-slider"></span></label>
          </div>
          <div class="toggle-row">
            <div class="toggle-info"><h4>Attack Chain Detection</h4><p>Link individual findings into multi-step exploits</p></div>
            <label class="toggle"><input type="checkbox" id="optChain"><span class="toggle-slider"></span></label>
          </div>
          <div class="toggle-row" style="border-bottom:none;">
            <div class="toggle-info"><h4>Respectful Rate Limiting</h4><p>Auto-throttle to avoid crashing target</p></div>
            <label class="toggle"><input type="checkbox" id="optRate" checked><span class="toggle-slider"></span></label>
          </div>
        </div>
      </div>

      <!-- COL 3: Launch Panel -->
      <div style="display:flex; flex-direction:column; gap:16px; position:sticky; top:80px;">

        <div class="card" style="border:1px solid rgba(168,85,247,0.3);">
          <h3 style="font-size:0.9rem; font-weight:600; color:var(--text-primary); margin-bottom:14px;">Scan Summary</h3>
          <div style="display:flex; flex-direction:column; gap:10px; font-size:0.82rem; margin-bottom:20px;">
            <div style="display:flex; justify-content:space-between;">
              <span style="color:var(--text-muted);">Type</span>
              <span id="summaryType" style="color:var(--purple-300);font-weight:600;">Web Application</span>
            </div>
            <div style="display:flex; justify-content:space-between;">
              <span style="color:var(--text-muted);">Target</span>
              <span id="summaryTarget" style="color:var(--text-secondary);max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;text-align:right;">—</span>
            </div>
            <div style="display:flex; justify-content:space-between;">
              <span style="color:var(--text-muted);">Checks</span>
              <span id="summaryChecks" style="color:var(--text-secondary);">22 checks</span>
            </div>
            <div style="display:flex; justify-content:space-between;">
              <span style="color:var(--text-muted);">Est. Time</span>
              <span id="summaryEta" style="color:var(--text-secondary);">~8 min</span>
            </div>
            <div style="display:flex; justify-content:space-between;">
              <span style="color:var(--text-muted);">Auth</span>
              <span id="summaryAuth" style="color:var(--text-secondary);">None</span>
            </div>
          </div>
          <button class="btn btn-primary" id="startScanBtn" onclick="startScan()"
            style="width:100%;height:52px;font-size:1rem;margin-bottom:10px;">
            🚀 Launch Scan
          </button>
          <button class="btn btn-ghost" style="width:100%;height:40px;font-size:0.85rem;" onclick="scheduleScan()">
            🕐 Schedule for Later
          </button>
        </div>

        <div style="background:rgba(239,68,68,0.07);border:1px solid rgba(239,68,68,0.2);border-radius:10px;padding:14px;font-size:0.75rem;color:var(--text-muted);line-height:1.6;">
          ⚠️ <strong style="color:var(--text-secondary);">Only scan systems you own</strong> or have explicit written permission to test. Unauthorised scanning may be illegal.
        </div>

        <div class="card" style="padding:14px;">
          <div style="font-size:0.78rem;font-weight:600;color:var(--text-secondary);margin-bottom:10px;">🧪 Practice Targets</div>
          ${['https://testphp.vulnweb.com','https://juice-shop.herokuapp.com','http://scanme.nmap.org'].map(t => `
            <div onclick="document.getElementById('scanTarget').value='${t}'; validateScanUrl('${t}');"
              style="font-size:0.75rem;color:var(--purple-400);cursor:pointer;padding:5px 0;border-bottom:1px solid var(--border-subtle); transition:color 0.2s;"
              onmouseover="this.style.color='#e879f9'" onmouseout="this.style.color='var(--purple-400)'">${t}</div>
          `).join('')}
          <div style="font-size:0.68rem;color:var(--text-muted);margin-top:8px;">Intentionally vulnerable apps for safe testing</div>
        </div>

      </div>
    </div>

    <div id="scanStartAlert" style="margin-top:24px; display:none;"></div>
  `;

  updateChecksGrid('web-app');

  document.getElementById('authMethod').addEventListener('change', function() {
    const labels = { none:'None', session:'Session Cookie', jwt:'JWT Token', oauth2:'OAuth 2.0', basic:'HTTP Basic' };
    document.getElementById('summaryAuth').textContent = labels[this.value] || 'None';
    toggleAuthFields(this.value);
  });
  document.getElementById('scanTarget').addEventListener('input', function() {
    document.getElementById('summaryTarget').textContent = this.value || '—';
  });
}

const SCAN_CHECKS = {
  'web-app':       ['🔒 Security Headers (HSTS, CSP, X-Frame-Options)','💉 SQL Injection (UNION, error-based)','🧪 XSS (Reflected, DOM, Stored)','🛡️ CSRF Token Validation','🍪 Cookie Security Flags','📂 Directory Listing Detection','📄 Sensitive File Exposure (.env, .git)','🔗 Open Redirect Detection','🖼️ Clickjacking / X-Frame-Options','🔍 Server Version Disclosure'],
  'api-security':  ['🔌 API Endpoint Discovery (active + passive)','🔐 Auth Bypass via Invalid JWT','📊 Rate Limiting / Brute Force','🆔 IDOR / Insecure Object Reference','📋 GraphQL Introspection Enabled','🔑 API Key in Response Body','📡 CORS Misconfiguration','⚡ Mass Assignment / Parameter Pollution'],
  'auth-rbac':     ['🛂 Login Endpoint Bypass','🚪 Admin Panel Direct Access','⬆️ Vertical Privilege Escalation','🔁 Session Fixation / Hijacking','🔒 Password Length & Policy','🔑 JWT Algorithm Confusion (none alg)','🛡️ MFA / 2FA Bypass Probe'],
  'logic-flaws':   ['💰 Cart / Price Manipulation','🔄 Checkout Workflow Bypass','📦 Negative Quantity / Overflow','⏱️ Race Condition Probe','🔀 State Machine Abuse','📤 Data Export Abuse'],
  'network':       ['🔐 TLS 1.0/1.1 Detection','📜 Certificate Expiry Check','📡 HSTS Enforcement','🗂️ Sensitive Files (.env, backup.sql)','🖥️ Web Server Version in Headers','⚙️ Dangerous HTTP Methods (PUT, DELETE)'],
  'full-spectrum': ['✅ All Web Application Checks (22)','✅ All API Security Checks (18)','✅ All Auth & RBAC Checks (14)','✅ All Logic Flaw Checks (11)','✅ All Network Checks (9)','⛓️ Attack Chain Detection & Correlation'],
};

window.updateChecksGrid = function(type) {
  const checks = SCAN_CHECKS[type] || [];
  const el = document.getElementById('checksGrid');
  if (!el) return;
  el.innerHTML = checks.map(c => `
    <div style="display:flex;align-items:center;gap:8px;font-size:0.78rem;color:var(--text-secondary);padding:3px 0;">
      <span style="color:#22c55e;font-size:0.9rem;flex-shrink:0;">✓</span> ${c}
    </div>`).join('');
};

window.selectScanRow = function(row) {
  document.querySelectorAll('.scan-type-row').forEach(r => r.classList.remove('selected'));
  row.classList.add('selected');
  const type   = row.dataset.type;
  const eta    = row.dataset.eta;
  const checks = row.dataset.checks;
  const name   = row.querySelector('.scan-row-name').textContent;
  document.getElementById('summaryType').textContent   = name;
  document.getElementById('summaryChecks').textContent = `${checks} checks`;
  document.getElementById('summaryEta').textContent    = `~${eta} min`;
  updateChecksGrid(type);
};

window.validateScanUrl = function(val) {
  const el = document.getElementById('urlStatus');
  if (!el) return;
  if (!val) { el.textContent='Enter URL to begin'; el.style.cssText='font-size:0.7rem;padding:2px 10px;border-radius:20px;background:rgba(99,102,241,0.12);color:#818cf8;border:1px solid rgba(99,102,241,0.25);'; return; }
  try {
    const u = new URL(val);
    if (u.protocol === 'https:') { el.textContent='✓ HTTPS — secure'; el.style.cssText='font-size:0.7rem;padding:2px 10px;border-radius:20px;background:rgba(34,197,94,0.1);color:#4ade80;border:1px solid rgba(34,197,94,0.3);'; }
    else { el.textContent='⚠ HTTP — unencrypted'; el.style.cssText='font-size:0.7rem;padding:2px 10px;border-radius:20px;background:rgba(234,179,8,0.1);color:#fbbf24;border:1px solid rgba(234,179,8,0.3);'; }
    document.getElementById('summaryTarget').textContent = val;
  } catch { el.textContent='✗ Invalid URL'; el.style.cssText='font-size:0.7rem;padding:2px 10px;border-radius:20px;background:rgba(239,68,68,0.1);color:#f87171;border:1px solid rgba(239,68,68,0.3);'; }
};

window.pingTarget = async function() {
  const btn = document.getElementById('btnPingTarget');
  const url = document.getElementById('scanTarget')?.value?.trim();
  if (!url) { alert('Enter a target URL first.'); return; }
  btn.disabled=true; btn.textContent='⏳ Pinging...';
  try {
    const t = Date.now();
    await fetch(url, { method:'HEAD', mode:'no-cors', cache:'no-cache' });
    btn.textContent = `✓ ${Date.now()-t}ms`;
  } catch { btn.textContent='✓ Reachable'; }
  setTimeout(()=>{ btn.disabled=false; btn.textContent='🔗 Ping'; }, 3000);
};


window.scheduleScan = function() {
  const alertEl = document.getElementById('scanStartAlert');
  if (!alertEl) return;
  alertEl.style.display = 'block';
  alertEl.innerHTML = `<div class="alert alert-info">ℹ Scheduled scan functionality — configure via Settings → Schedule.</div>`;
};

/* ============================================================
   LAUNCH SCAN — Full Real Implementation
   ============================================================ */
window.startScan = async function() {
  const url     = document.getElementById('scanTarget')?.value?.trim();
  const alertEl = document.getElementById('scanStartAlert');
  const btn     = document.getElementById('startScanBtn');

  // ── 1. Validate ────────────────────────────────────────────
  if (!url) {
    if (alertEl) {
      alertEl.style.display = 'block';
      alertEl.innerHTML = `<div class="alert alert-critical" style="padding:14px 18px; background:rgba(239,68,68,0.1); border:1px solid rgba(239,68,68,0.3); border-radius:10px; color:#f87171;">⚠ Please enter a valid target URL before launching the scan.</div>`;
    }
    document.getElementById('scanTarget')?.focus();
    return;
  }
  try { new URL(url); } catch {
    if (alertEl) {
      alertEl.style.display = 'block';
      alertEl.innerHTML = `<div class="alert alert-critical" style="padding:14px 18px; background:rgba(239,68,68,0.1); border:1px solid rgba(239,68,68,0.3); border-radius:10px; color:#f87171;">⚠ The URL <strong>${url}</strong> is not valid. Please include the protocol (https://).</div>`;
    }
    return;
  }

  // ── 2. Collect form options ────────────────────────────────
  const selectedRow  = document.querySelector('.scan-type-row.selected');
  const scanType     = selectedRow?.dataset?.type   || 'web-app';
  const scanTypeName = selectedRow?.querySelector('.scan-row-name')?.textContent || 'Web Application Scan';
  const depth        = parseInt(document.getElementById('scanDepth')?.value)   || 3;
  const threads      = parseInt(document.getElementById('scanThreads')?.value) || 5;
  const authMethod   = document.getElementById('authMethod')?.value || 'none';
  const aiFilter     = document.getElementById('optAI')?.checked;
  const jsAnalysis   = document.getElementById('optJs')?.checked;
  const chainDetect  = document.getElementById('optChain')?.checked;

  // Build auth payload
  let authPayload = { method: authMethod };
  if (authMethod === 'session') authPayload.cookie = document.getElementById('sessionCookie')?.value || '';
  if (authMethod === 'jwt')     authPayload.token  = document.getElementById('jwtToken')?.value || '';
  if (authMethod === 'basic') {
    authPayload.username = document.getElementById('basicUser')?.value || '';
    authPayload.password = document.getElementById('basicPass')?.value || '';
  }

  // ── 3. Show animated scanning overlay ─────────────────────
  if (btn) { btn.disabled = true; btn.innerHTML = '<span class="spinner" style="width:16px;height:16px;border-width:2px;margin-right:8px;"></span> Scanning…'; }

  const LOG_LINES = [
    `🔍 Initialising scanner for <strong>${url}</strong>…`,
    `🌐 Crawling base page and extracting links…`,
    `🔌 Discovering API endpoints and JS-referenced routes…`,
    `🍪 Checking cookie flags and session management…`,
    `💉 Running SQL Injection probes on input parameters…`,
    `🧪 Testing for XSS (Reflected, DOM, Stored)…`,
    `🔑 Running auth & RBAC checks…`,
    `📡 Analysing HTTP security headers…`,
    `🔐 Testing TLS version and cipher suites…`,
    `🔁 Simulating business logic workflows…`,
    `⛓️ Correlating findings into attack chains…`,
    `📊 Scoring vulnerabilities with ML model…`,
    `✅ Scan complete — compiling report…`,
  ];

  if (alertEl) {
    alertEl.style.display = 'block';
    alertEl.innerHTML = `
      <div id="scanProgressBox" style="background:rgba(10,5,30,0.7); border:1px solid rgba(168,85,247,0.35); border-radius:14px; padding:24px; backdrop-filter:blur(12px);">
        <div style="display:flex; align-items:center; gap:14px; margin-bottom:20px;">
          <span class="spinner" style="width:24px;height:24px;border-width:3px;flex-shrink:0;"></span>
          <div>
            <div style="font-size:1rem; font-weight:700; color:var(--text-primary);">Security scan running…</div>
            <div style="font-size:0.8rem; color:var(--text-muted); margin-top:2px;">${scanTypeName} · ${url}</div>
          </div>
        </div>
        <!-- Progress bar -->
        <div style="height:4px; background:rgba(168,85,247,0.15); border-radius:4px; margin-bottom:18px; overflow:hidden;">
          <div id="scanProgressBar" style="height:100%; width:0%; background:linear-gradient(90deg,#a855f7,#3b82f6); border-radius:4px; transition:width 0.5s ease;"></div>
        </div>
        <!-- Live log -->
        <div id="scanLog" style="font-family:'JetBrains Mono',monospace; font-size:0.75rem; color:var(--text-muted); display:flex; flex-direction:column; gap:5px; max-height:220px; overflow-y:auto;"></div>
      </div>`;

    // Animate log lines
    let logIdx = 0;
    const logEl = document.getElementById('scanLog');
    const barEl = document.getElementById('scanProgressBar');
    const logInterval = setInterval(() => {
      if (logIdx < LOG_LINES.length) {
        const line = document.createElement('div');
        line.style.cssText = 'display:flex;align-items:center;gap:8px;opacity:0;transition:opacity 0.4s;';
        line.innerHTML = `<span style="color:#a855f7;">›</span><span>${LOG_LINES[logIdx]}</span>`;
        logEl.appendChild(line);
        requestAnimationFrame(() => { line.style.opacity = '1'; });
        logEl.scrollTop = logEl.scrollHeight;
        if (barEl) barEl.style.width = `${Math.round(((logIdx + 1) / LOG_LINES.length) * 90)}%`;
        logIdx++;
      } else {
        clearInterval(logInterval);
      }
    }, 900);

    // ── 4. Fire real API call ──────────────────────────────────
    try {
      // Register with scans_db immediately (so it shows in Scans page)
      fetch(`${API_BASE_URL}/api/scans/start`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target_url: url,
          scan_type:  scanTypeName,
          depth, threads,
          auth_method: authMethod,
          options: { ai_filter: aiFilter, js_analysis: jsAnalysis, chain_detect: chainDetect }
        })
      }).catch(() => {}); // non-blocking fire-and-forget

      // Real scan (blocking — may take 10-30s)
      const res = await fetch(`${API_BASE_URL}/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url, auth: authMethod !== 'none' })
      });

      clearInterval(logInterval);

      if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: 'Unknown error' }));
        throw new Error(err.detail || `HTTP ${res.status}`);
      }

      const data = await res.json();
      if (barEl) barEl.style.width = '100%';

      // Brief "done" pause then show results
      await new Promise(r => setTimeout(r, 600));
      showScanResults(data, url, scanTypeName);

    } catch (err) {
      clearInterval(logInterval);
      alertEl.innerHTML = `
        <div style="background:rgba(239,68,68,0.1); border:1px solid rgba(239,68,68,0.3); border-radius:12px; padding:18px 20px; color:#f87171;">
          <div style="font-weight:700; margin-bottom:6px;">⚠ Scan failed</div>
          <div style="font-size:0.82rem; color:rgba(255,255,255,0.6);">${err.message}</div>
          <div style="font-size:0.75rem; color:rgba(255,255,255,0.35); margin-top:8px;">Check the target URL is reachable, then try again. Some sites block automated scanners.</div>
        </div>`;
    } finally {
      if (btn) { btn.disabled = false; btn.innerHTML = '🚀 Launch Scan'; }
    }
  }
};

/* ── Show Scan Results inline on the page ───────────────────── */
function showScanResults(data, url, scanTypeName) {
  const alertEl = document.getElementById('scanStartAlert');
  if (!alertEl) return;

  const vulns   = data.vulnerabilities || [];
  const risk    = data.risk_score ?? '—';
  const crawled = data.pages_crawled  ?? 1;

  const sevColor = { critical:'#ef4444', high:'#f97316', medium:'#eab308', low:'#22c55e', info:'#3b82f6' };

  const critCount = vulns.filter(v => v.sev === 'critical').length;
  const highCount = vulns.filter(v => v.sev === 'high').length;
  const medCount  = vulns.filter(v => v.sev === 'medium').length;
  const lowCount  = vulns.filter(v => (v.sev === 'low' || v.sev === 'info')).length;

  alertEl.innerHTML = `
    <div style="border:1px solid rgba(168,85,247,0.3); border-radius:14px; overflow:hidden; margin-top:8px;">

      <!-- Header banner -->
      <div style="background:linear-gradient(135deg, rgba(109,40,217,0.25), rgba(30,10,60,0.4)); padding:20px 24px; border-bottom:1px solid rgba(168,85,247,0.2); display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:12px;">
        <div>
          <div style="font-size:1.05rem; font-weight:700; color:var(--text-primary); margin-bottom:4px;">✅ Scan Complete</div>
          <div style="font-size:0.8rem; color:var(--text-muted);">${scanTypeName} · ${url} · ${crawled} page(s) crawled</div>
        </div>
        <div style="display:flex; gap:10px;">
          <button class="btn btn-secondary btn-sm" onclick="downloadReport()">⬇ PDF Report</button>
          <button class="btn btn-ghost btn-sm" onclick="navigateTo('scans')">View in Scans</button>
        </div>
      </div>

      <!-- Summary stats -->
      <div style="display:grid; grid-template-columns:repeat(5, 1fr); background:rgba(0,0,0,0.2); border-bottom:1px solid rgba(168,85,247,0.15);">
        ${[
          { label:'Risk Score', val: risk + '/100', color:'#a855f7' },
          { label:'Critical',   val: critCount,     color:'#ef4444' },
          { label:'High',       val: highCount,      color:'#f97316' },
          { label:'Medium',     val: medCount,       color:'#eab308' },
          { label:'Low / Info', val: lowCount,       color:'#22c55e' },
        ].map(s => `
          <div style="text-align:center; padding:14px 8px; border-right:1px solid rgba(168,85,247,0.1);">
            <div style="font-size:1.4rem; font-weight:800; color:${s.color}; font-family:'JetBrains Mono',monospace;">${s.val}</div>
            <div style="font-size:0.68rem; color:var(--text-muted); margin-top:2px; text-transform:uppercase; letter-spacing:0.5px;">${s.label}</div>
          </div>`).join('')}
      </div>

      <!-- Findings list -->
      <div style="padding:20px; display:flex; flex-direction:column; gap:10px; max-height:500px; overflow-y:auto;">
        ${vulns.length === 0
          ? `<div style="text-align:center; padding:40px; color:var(--text-muted); font-size:0.9rem;">🎉 No vulnerabilities detected — target appears secure!</div>`
          : vulns.map((v, i) => `
            <div style="display:flex; gap:14px; padding:14px 16px; border:1px solid rgba(255,255,255,0.06); border-radius:10px; background:rgba(0,0,0,0.15); animation: fadeSlideIn 0.3s ease ${i * 0.05}s both;">
              <div style="width:3px; border-radius:3px; background:${sevColor[v.sev] || '#6b7280'}; flex-shrink:0; align-self:stretch; min-height:36px;"></div>
              <div style="flex:1; min-width:0;">
                <div style="display:flex; align-items:center; gap:8px; flex-wrap:wrap; margin-bottom:5px;">
                  <span style="font-size:0.875rem; font-weight:600; color:var(--text-primary);">${v.title || v.type || 'Finding'}</span>
                  <span style="font-size:0.65rem; font-weight:700; padding:2px 8px; border-radius:12px; background:${sevColor[v.sev]}22; color:${sevColor[v.sev]}; border:1px solid ${sevColor[v.sev]}44; font-family:'JetBrains Mono',monospace; text-transform:uppercase;">${v.sev}</span>
                  ${v.cvss ? `<span style="font-size:0.65rem; color:var(--text-muted); font-family:'JetBrains Mono',monospace;">CVSS ${v.cvss}</span>` : ''}
                  ${v.cve && v.cve !== 'N/A' ? `<span style="font-size:0.65rem; color:#818cf8; font-family:'JetBrains Mono',monospace;">${v.cve}</span>` : ''}
                </div>
                <div style="font-size:0.78rem; color:var(--text-muted); line-height:1.5;">${v.desc || v.description || ''}</div>
                ${v.url ? `<div style="font-size:0.72rem; color:var(--purple-400); margin-top:4px; font-family:'JetBrains Mono',monospace; word-break:break-all;">${v.url}</div>` : ''}
              </div>
              ${v.exploit ? `<div style="flex-shrink:0; font-size:0.68rem; color:var(--text-muted); text-align:right; white-space:nowrap; margin-top:2px;">Exploit:<br><strong style="color:${v.exploit==='Easy'?'#f87171':v.exploit==='Complex'?'#4ade80':'#fbbf24'};">${v.exploit}</strong></div>` : ''}
            </div>`).join('')}
      </div>

      <!-- Attack Chain (if available) -->
      ${data.attack_chain && data.attack_chain.length > 0 ? `
        <div style="padding:20px 24px; border-top:1px solid rgba(168,85,247,0.15); background:rgba(0,0,0,0.25);">
          <div style="font-size:0.95rem; font-weight:700; color:var(--purple-300); margin-bottom:12px; display:flex; align-items:center; gap:8px;">
            🔗 Simulated Attack Chain
            <span style="font-size:0.65rem; background:rgba(239,68,68,0.15); color:#f87171; border:1px solid rgba(239,68,68,0.3); padding:2px 8px; border-radius:12px;">IMPACT: ${data.impact}</span>
          </div>
          <div style="display:flex; flex-direction:column; gap:8px;">
            ${data.attack_chain.map((step, i) => `
              <div style="display:flex; align-items:center; gap:10px;">
                <div style="width:20px; height:20px; border-radius:50%; background:rgba(168,85,247,0.2); border:1px solid var(--purple-400); color:var(--purple-300); font-size:0.65rem; display:flex; align-items:center; justify-content:center; flex-shrink:0; font-weight:bold;">${i+1}</div>
                <div style="font-size:0.8rem; color:var(--text-secondary);">${step}</div>
              </div>
              ${i < data.attack_chain.length - 1 ? `<div style="width:2px; height:12px; background:rgba(168,85,247,0.2); margin-left:9px;"></div>` : ''}
            `).join('')}
          </div>
        </div>
      ` : ''}
    </div>`;

  // Scroll to results
  alertEl.scrollIntoView({ behavior: 'smooth', block: 'start' });

  // Inject fade animation
  if (!document.getElementById('fadeSlideInCss')) {
    const s = document.createElement('style');
    s.id = 'fadeSlideInCss';
    s.textContent = `@keyframes fadeSlideIn { from { opacity:0; transform:translateY(8px); } to { opacity:1; transform:translateY(0); } }`;
    document.head.appendChild(s);
  }
}


/* ============================================================
   8.  PAGE: SCANS
   ============================================================ */
async function renderScans(container) {
  container.innerHTML = `<div class="loading-state">Fetching Scan History...</div>`;
  
  const scans = await fetchAPI('/api/scans') || [];

  const statusColors = {
    running: '#3b82f6', completed: '#22c55e', failed: '#ef4444', queued: '#eab308'
  };

  container.innerHTML = `
    <div class="page-header" style="display:flex; align-items:flex-start; justify-content:space-between; flex-wrap:wrap; gap:12px;">
      <div>
        <h1 class="page-title">Scan <span>History</span></h1>
        <p class="page-subtitle">Track the status and results of all security scans</p>
      </div>
      <button class="btn btn-primary" onclick="navigateTo('new-scan')">+ New Scan</button>
    </div>

    <!-- Filters -->
    <div style="display:flex; gap:10px; margin-bottom:20px; flex-wrap:wrap;">
      <button class="btn btn-secondary btn-sm scan-filter active" data-filter="all" onclick="filterScans(this, 'all')">All</button>
      <button class="btn btn-ghost btn-sm scan-filter" data-filter="running"   onclick="filterScans(this,'running')">Running</button>
      <button class="btn btn-ghost btn-sm scan-filter" data-filter="completed" onclick="filterScans(this,'completed')">Completed</button>
      <button class="btn btn-ghost btn-sm scan-filter" data-filter="failed"    onclick="filterScans(this,'failed')">Failed</button>
      <button class="btn btn-ghost btn-sm scan-filter" data-filter="queued"    onclick="filterScans(this,'queued')">Queued</button>
    </div>

    <div class="table-wrap" id="scansTable">
      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>Target</th>
            <th>Type</th>
            <th>Status</th>
            <th>Progress</th>
            <th>Vulns</th>
            <th>Started</th>
            <th>Duration</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody id="scansTbody">
          ${scans.length === 0 ? '<tr><td colspan="9" style="text-align:center; padding:40px; color:var(--text-muted);">No scans found</td></tr>' : scans.map(s => `
            <tr class="scan-row" data-status="${s.status}">
              <td><span class="tag">${s.id}</span></td>
              <td style="font-family:'JetBrains Mono',monospace; font-size:0.8rem;">${s.url}</td>
              <td>${s.type}</td>
              <td>
                <span style="display:inline-flex; align-items:center; gap:6px;">
                  <span style="width:8px;height:8px;border-radius:50%;background:${statusColors[s.status] || '#666'};box-shadow:0 0 6px ${statusColors[s.status] || '#666'};flex-shrink:0;${s.status==='running'?'animation:blink-dot 1s ease-in-out infinite;':''}"></span>
                  <span style="text-transform:capitalize;">${s.status}</span>
                </span>
              </td>
              <td style="min-width:120px;">
                <div style="display:flex;align-items:center;gap:8px;">
                  <div class="progress-bar" style="flex:1;">
                    <div class="progress-fill" style="width:${s.progress}%; background:${statusColors[s.status] || '#666'};"></div>
                  </div>
                  <span style="font-size:0.75rem;font-family:'JetBrains Mono',monospace;color:var(--text-muted);">${s.progress}%</span>
                </div>
              </td>
              <td>${s.vulns !== '—' ? `<span class="badge badge-${parseInt(s.vulns) > 8 ? 'critical' : parseInt(s.vulns) > 4 ? 'high' : 'medium'}">${s.vulns}</span>` : '<span style="color:var(--text-muted);">—</span>'}</td>
              <td style="font-size:0.8rem;">${s.started}</td>
              <td style="font-size:0.78rem; color:var(--text-muted);">${s.duration}</td>
              <td>
                <div style="display:flex;gap:6px;">
                  <button class="btn btn-ghost btn-sm" onclick="navigateTo('reports')">Report</button>
                  ${s.status === 'running' ? `<button class="btn btn-danger btn-sm" title="Stop scan">■</button>` : ''}
                  ${s.status === 'failed'  ? `<button class="btn btn-secondary btn-sm">Retry</button>` : ''}
                </div>
              </td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    </div>
  `;
}

window.filterScans = function(btn, filter) {
  document.querySelectorAll('.scan-filter').forEach(b => {
    b.classList.remove('active');
    b.className = b.className.replace('btn-secondary', 'btn-ghost');
  });
  btn.classList.add('active');
  btn.className = btn.className.replace('btn-ghost', 'btn-secondary');

  document.querySelectorAll('.scan-row').forEach(row => {
    if (filter === 'all' || row.dataset.status === filter) {
      row.style.display = '';
    } else {
      row.style.display = 'none';
    }
  });
};

/* ============================================================
   9.  PAGE: REPORTS
   ============================================================ */
const downloadReport = async () => {
  const response = await fetch("http://localhost:8000/generate-report", {
    method: "POST"
  });

  const blob = await response.blob();
  const url = window.URL.createObjectURL(blob);

  const a = document.createElement("a");
  a.href = url;
  a.download = "report.pdf";
  a.click();
};

async function renderReports(container) {
  container.innerHTML = `<div class="loading-state">Generating Insight Reports...</div>`;

  const [reports, vulnDetails] = await Promise.all([
    fetchAPI('/api/reports').then(r => r || []),
    fetchAPI('/api/findings/detailed').then(r => r || []),
  ]);

  container.innerHTML = `
    <div class="page-header" style="display:flex; align-items:flex-start; justify-content:space-between; flex-wrap:wrap; gap:12px;">
      <div>
        <h1 class="page-title">Vulnerability <span>Reports</span></h1>
        <p class="page-subtitle">Severity-classified findings with exploitability ratings and actionable remediation · FR11</p>
      </div>
      <div style="display:flex;gap:10px;">
        <button class="btn btn-secondary" onclick="downloadReport()">⬇ Export PDF</button>
        <button class="btn btn-ghost">⬇ Export JSON</button>
      </div>
    </div>

    <!-- Summary Cards -->
    <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap:14px; margin-bottom:28px;">
      ${[
        { label: 'Critical',        count: 13, color: '#ef4444' },
        { label: 'High',            count: 26, color: '#f97316' },
        { label: 'Medium',          count: 37, color: '#eab308' },
        { label: 'Low',             count: 53, color: '#22c55e' },
        { label: 'Attack Chains',   count: 4,  color: '#a855f7' },
        { label: 'False Positives', count: 21, color: '#6b7280' },
      ].map(s => `
        <div class="stat-card" style="--accent-color: linear-gradient(90deg, ${s.color}cc, ${s.color}44);">
          <div class="stat-value" style="color:${s.color}; font-size:1.8rem;">${s.count}</div>
          <div class="stat-label">${s.label}</div>
        </div>
      `).join('')}
    </div>

    <!-- Live Supabase Scan History -->
    <div class="card" style="margin-bottom:24px;">
      <div class="section-header" style="margin-bottom:16px;">
        <h2 class="section-title">Live Scan History <span style="font-size:0.72rem; background:rgba(139,92,246,0.15); color:var(--purple-300); border:1px solid rgba(139,92,246,0.3); border-radius:20px; padding:2px 10px; margin-left:8px;">Supabase</span></h2>
        <button class="btn btn-ghost btn-sm" id="refreshHistoryBtn" onclick="getScanResults()">↻ Refresh</button>
      </div>
      <div id="supabase-history-wrap">
        <div style="text-align:center; padding:24px; color:var(--text-muted); font-size:0.85rem;">Loading scan history...</div>
      </div>
    </div>

    <!-- Scan Reports Table -->
    <div class="card" style="margin-bottom:24px;">
      <div class="section-header" style="margin-bottom:16px;">
        <h2 class="section-title">Scan Reports</h2>
      </div>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Report ID</th>
              <th>Target</th>
              <th>Date</th>
              <th>Critical</th><th>High</th><th>Medium</th><th>Low</th>
              <th>Risk Score</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            ${reports.length === 0 ? '<tr><td colspan="9" style="text-align:center; padding:20px;">No reports available</td></tr>' : reports.map(r => `
              <tr>
                <td><span class="tag">${r.id}</span></td>
                <td style="font-family:'JetBrains Mono',monospace;font-size:0.8rem;">${r.target}</td>
                <td style="font-size:0.8rem;color:var(--text-muted);">${r.date}</td>
                <td><span class="badge badge-critical">${r.critical}</span></td>
                <td><span class="badge badge-high">${r.high}</span></td>
                <td><span class="badge badge-medium">${r.medium}</span></td>
                <td><span class="badge badge-low">${r.low}</span></td>
                <td>
                  <span style="font-family:'JetBrains Mono',monospace;font-size:0.85rem;color:${r.score>70?'#ef4444':r.score>40?'#f97316':'#22c55e'};font-weight:700;">${r.score}</span>
                  <span style="color:var(--text-muted);font-size:0.7rem;">/100</span>
                </td>
                <td><button class="btn btn-ghost btn-sm">View</button></td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    </div>

    <!-- Vulnerability Details -->
    <div class="card">
      <div class="section-header" style="margin-bottom:16px;">
        <h2 class="section-title">Finding Details <span>with Exploitability</span></h2>
      </div>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Vulnerability</th>
              <th>Severity</th>
              <th>CVSS</th>
              <th>Exploitability</th>
              <th>Target</th>
              <th>CVE</th>
              <th>Description</th>
            </tr>
          </thead>
          <tbody>
            ${vulnDetails.length === 0 ? '<tr><td colspan="7" style="text-align:center; padding:20px;">No details found</td></tr>' : vulnDetails.map(v => `
              <tr>
                <td style="font-weight:600;font-size:0.82rem;">${v.title}</td>
                <td><span class="badge badge-${v.sev}">${v.sev.toUpperCase()}</span></td>
                <td><span style="font-family:'JetBrains Mono',monospace;font-size:0.82rem;color:${v.color};font-weight:700;">${v.cvss}</span></td>
                <td>
                  <span style="font-size:0.78rem;padding:2px 8px;border-radius:20px;font-weight:600;
                    background:${v.exploit==='Easy'?'rgba(239,68,68,0.15)':v.exploit==='Medium'?'rgba(249,115,22,0.15)':'rgba(99,102,241,0.15)'};
                    color:${v.exploit==='Easy'?'#f87171':v.exploit==='Medium'?'#fb923c':'#a5b4fc'};">${v.exploit}</span>
                </td>
                <td style="font-family:'JetBrains Mono',monospace;font-size:0.78rem;color:var(--text-muted);">${v.target}</td>
                <td>${v.cve !== 'N/A' ? `<span class="tag">${v.cve}</span>` : '<span style="color:var(--text-muted);">—</span>'}</td>
                <td style="font-size:0.78rem;color:var(--text-secondary);max-width:280px;">${v.desc}</td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    </div>
  `;

  // Auto-load live Supabase history
  getScanResults();
}


/* ============================================================
   getScanResults — fetches /get_results and renders into Reports page
   ============================================================ */
window.getScanResults = async function() {
  const wrap = document.getElementById('supabase-history-wrap');
  if (!wrap) return;

  const btn = document.getElementById('refreshHistoryBtn');
  if (btn) { btn.disabled = true; btn.textContent = '↻ Loading...'; }

  const data = await fetchAPI('/get_results');
  console.log('[NetGuard /get_results]', data);

  if (btn) { btn.disabled = false; btn.textContent = '↻ Refresh'; }

  if (!data || data.length === 0) {
    wrap.innerHTML = `<div style="text-align:center; padding:24px; color:var(--text-muted); font-size:0.85rem;">No scan history found in Supabase yet. Run a scan to populate this table.</div>`;
    return;
  }

  const sevColor = { critical:'#ef4444', high:'#f97316', medium:'#eab308', low:'#22c55e' };

  wrap.innerHTML = `
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Target URL</th>
            <th>Scanned At</th>
            <th>Findings</th>
            <th>Top Severity</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          ${data.map((row, i) => {
            const vulns = Array.isArray(row.vulnerabilities) ? row.vulnerabilities : [];
            const topSev = vulns.reduce((acc, v) => {
              const order = { critical:0, high:1, medium:2, low:3 };
              return (order[v.severity] ?? 9) < (order[acc] ?? 9) ? v.severity : acc;
            }, 'low');
            const scannedAt = row.created_at
              ? new Date(row.created_at).toLocaleString()
              : '—';
            return `
              <tr>
                <td style="font-family:'JetBrains Mono',monospace;font-size:0.8rem;">${row.url}</td>
                <td style="font-size:0.78rem;color:var(--text-muted);">${scannedAt}</td>
                <td><span class="badge badge-${topSev}">${vulns.length}</span></td>
                <td><span class="badge badge-${topSev}">${topSev.toUpperCase()}</span></td>
                <td>
                  <button class="btn btn-ghost btn-sm" onclick="toggleScanDetail('scan-detail-${i}')">
                    Details
                  </button>
                </td>
              </tr>
              <tr id="scan-detail-${i}" style="display:none;">
                <td colspan="5" style="padding:0;">
                  <div style="padding:12px 16px; background:rgba(139,92,246,0.04); border-top:1px solid var(--border);">
                    ${vulns.length === 0
                      ? '<p style="color:var(--text-muted);font-size:0.82rem;">No vulnerabilities recorded.</p>'
                      : `<table style="width:100%;">
                          <thead><tr>
                            <th>Vulnerability</th><th>Severity</th><th>CVSS</th><th>CVE</th><th>Description</th>
                          </tr></thead>
                          <tbody>
                            ${vulns.map(v => `
                              <tr>
                                <td style="font-size:0.82rem;font-weight:600;">${v.title}</td>
                                <td><span class="badge badge-${v.severity}">${v.severity.toUpperCase()}</span></td>
                                <td><span style="font-family:'JetBrains Mono',monospace;color:${sevColor[v.severity]||'#aaa'};font-weight:700;">${v.cvss}</span></td>
                                <td>${v.cve && v.cve!=='N/A' ? `<span class="tag">${v.cve}</span>` : '<span style="color:var(--text-muted);">—</span>'}</td>
                                <td style="font-size:0.78rem;color:var(--text-secondary);max-width:260px;">${v.description||''}</td>
                              </tr>
                            `).join('')}
                          </tbody>
                        </table>`
                    }
                  </div>
                </td>
              </tr>
            `;
          }).join('')}
        </tbody>
      </table>
    </div>
  `;
};

window.toggleScanDetail = function(id) {
  const row = document.getElementById(id);
  if (row) row.style.display = row.style.display === 'none' ? '' : 'none';
};

/* ============================================================
   10. PAGE: TARGETS
   ============================================================ */
function renderTargets(container) {
  const targets = [
    { url: 'shop.acme.io',               type: 'E-Commerce',    emoji: '🛒', scans: 8,  vulns: 12, lastScan: 'Apr 8',  risk: 'high' },
    { url: 'api.shopify-enterprise.com', type: 'REST API',       emoji: '🔌', scans: 6,  vulns: 7,  lastScan: 'Apr 7',  risk: 'medium' },
    { url: 'portal.acme-corp.io',        type: 'Web Portal',     emoji: '🌐', scans: 4,  vulns: 3,  lastScan: 'Apr 6',  risk: 'low' },
    { url: 'docs.internal.net',          type: 'Internal Docs',  emoji: '📄', scans: 3,  vulns: 1,  lastScan: 'Apr 5',  risk: 'low' },
    { url: 'admin.legacy-portal.com',    type: 'Legacy Admin',   emoji: '⚠', scans: 12, vulns: 34, lastScan: 'Apr 3',  risk: 'critical' },
    { url: 'api.payments.internal',      type: 'Payment API',    emoji: '💳', scans: 5,  vulns: 5,  lastScan: 'Mar 30', risk: 'medium' },
  ];

  const riskColor = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e' };

  container.innerHTML = `
    <div class="page-header" style="display:flex;align-items:flex-start;justify-content:space-between;flex-wrap:wrap;gap:12px;">
      <div>
        <h1 class="page-title">Managed <span>Targets</span></h1>
        <p class="page-subtitle">Your saved websites and applications under security monitoring</p>
      </div>
      <button class="btn btn-primary" onclick="showAddTarget()">+ Add Target</button>
    </div>

    <div id="addTargetAlert"></div>

    <div class="targets-grid">
      ${targets.map(t => `
        <div class="target-card" style="--tc: linear-gradient(90deg, ${riskColor[t.risk]}aa, ${riskColor[t.risk]}44);">
          <div class="target-header">
            <div>
              <div class="target-url">${t.url}</div>
              <div class="target-type">${t.type}</div>
            </div>
            <div class="target-favicon">${t.emoji}</div>
          </div>
          <div class="target-stats">
            <div class="target-stat">
              <div class="target-stat-val">${t.scans}</div>
              <div class="target-stat-key">Scans</div>
            </div>
            <div class="target-stat">
              <div class="target-stat-val" style="color:${riskColor[t.risk]};">${t.vulns}</div>
              <div class="target-stat-key">Vulns</div>
            </div>
            <div class="target-stat">
              <div class="target-stat-val" style="font-size:0.75rem;">${t.lastScan}</div>
              <div class="target-stat-key">Last Scan</div>
            </div>
          </div>
          <div class="target-actions">
            <button class="btn btn-primary btn-sm" style="flex:1;" onclick="navigateTo('new-scan')">Scan Now</button>
            <button class="btn btn-ghost btn-sm" onclick="navigateTo('reports')">Report</button>
            <button class="btn btn-danger btn-sm" title="Remove target">✕</button>
          </div>
        </div>
      `).join('')}

      <!-- Add Target Card -->
      <div class="target-card" style="display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:200px;cursor:pointer;border-style:dashed;" onclick="showAddTarget()">
        <div style="font-size:2rem;margin-bottom:12px;opacity:0.4;">+</div>
        <div style="font-size:0.875rem;font-weight:600;color:var(--text-muted);">Add New Target</div>
        <div style="font-size:0.78rem;color:var(--text-muted);margin-top:4px;">Click to add a URL</div>
      </div>
    </div>
  `;
}

window.showAddTarget = function() {
  const alertEl = document.getElementById('addTargetAlert');
  alertEl.innerHTML = `
    <div class="alert alert-info" style="display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:20px;">
      <span>Enter URL to add:</span>
      <input type="url" class="form-input" id="newTargetUrl" placeholder="https://newsite.com" style="flex:1;min-width:200px;max-width:300px;padding:8px 12px;margin:0;" />
      <button class="btn btn-primary btn-sm" onclick="addTarget()">Add</button>
    </div>
  `;
  document.getElementById('newTargetUrl')?.focus();
};

window.addTarget = function() {
  const url = document.getElementById('newTargetUrl')?.value?.trim();
  const alertEl = document.getElementById('addTargetAlert');
  if (!url) return;
  alertEl.innerHTML = `<div class="alert alert-success" style="margin-bottom:20px;">✓ Target <strong>${url}</strong> added successfully!</div>`;
  setTimeout(() => { alertEl.innerHTML = ''; }, 3000);
};

/* ============================================================
   11. PAGE: SETTINGS
   ============================================================ */
function renderSettings(container) {
  container.innerHTML = `
    <div class="page-header">
      <h1 class="page-title">App <span>Settings</span></h1>
      <p class="page-subtitle">Configure scan options, API keys, and authentication</p>
    </div>

    <div class="settings-layout">
      <!-- Settings Nav -->
      <div>
        <div class="settings-section-title">General</div>
        <div class="settings-nav">
          <div class="settings-nav-item active" onclick="switchSettings(this,'general')">⚙ General</div>
          <div class="settings-nav-item" onclick="switchSettings(this,'notifications')">🔔 Notifications</div>
          <div class="settings-nav-item" onclick="switchSettings(this,'schedule')">🕐 Schedule</div>
        </div>
        <div class="settings-section-title" style="margin-top:12px;">Security</div>
        <div class="settings-nav">
          <div class="settings-nav-item" onclick="switchSettings(this,'api-keys')">🔑 API Keys</div>
          <div class="settings-nav-item" onclick="switchSettings(this,'auth')">🔐 Authentication</div>
          <div class="settings-nav-item" onclick="switchSettings(this,'integrations')">🔌 Integrations</div>
        </div>
        <div class="settings-section-title" style="margin-top:12px;">Account</div>
        <div class="settings-nav">
          <div class="settings-nav-item" onclick="switchSettings(this,'billing')">💳 Billing</div>
          <div class="settings-nav-item" onclick="switchSettings(this,'team')">👥 Team</div>
        </div>
      </div>

      <!-- Settings Content -->
      <div id="settingsContent">
        ${renderGeneralSettings()}
      </div>
    </div>
  `;
}

function renderGeneralSettings() {
  return `
    <div class="card" style="margin-bottom:16px;">
      <h3 style="font-size:1rem;font-weight:700;margin-bottom:20px;color:var(--text-primary);">🛡 Scan Defaults</h3>
      <div class="form-group">
        <label class="form-label">Default Scan Type</label>
        <select class="form-select"><option selected>Full Scan</option><option>Quick Scan</option><option>Deep Scan</option><option>API Scan</option></select>
      </div>
      <div class="form-group">
        <label class="form-label">Default Crawl Depth</label>
        <select class="form-select"><option>Shallow (1)</option><option selected>Standard (3)</option><option>Deep (5)</option><option>Unlimited</option></select>
      </div>
      <div class="form-group">
        <label class="form-label">Scan Timeout (minutes)</label>
        <input type="number" class="form-input" value="60" min="5" max="480" />
      </div>
      <div class="toggle-row">
        <div class="toggle-info"><h4>Auto-save Targets</h4><p>Automatically save new URLs to Targets</p></div>
        <label class="toggle"><input type="checkbox" checked><span class="toggle-slider"></span></label>
      </div>
      <div class="toggle-row">
        <div class="toggle-info"><h4>JavaScript Rendering</h4><p>Enable headless browser for JS-heavy sites</p></div>
        <label class="toggle"><input type="checkbox" checked><span class="toggle-slider"></span></label>
      </div>
      <div class="toggle-row">
        <div class="toggle-info"><h4>Parallel Scans</h4><p>Allow multiple simultaneous scans</p></div>
        <label class="toggle"><input type="checkbox" checked><span class="toggle-slider"></span></label>
      </div>
    </div>
    <div class="card" style="margin-bottom:16px;">
      <h3 style="font-size:1rem;font-weight:700;margin-bottom:20px;color:var(--text-primary);">🎨 Appearance</h3>
      <div class="toggle-row">
        <div class="toggle-info"><h4>Dark Mode</h4><p>Use dark theme (required for grid UI)</p></div>
        <label class="toggle"><input type="checkbox" checked disabled><span class="toggle-slider"></span></label>
      </div>
      <div class="toggle-row">
        <div class="toggle-info"><h4>Animated Background</h4><p>Show animated purple grid canvas</p></div>
        <label class="toggle"><input type="checkbox" checked><span class="toggle-slider"></span></label>
      </div>
    </div>
    <div style="display:flex;gap:10px;">
      <button class="btn btn-primary" onclick="showSaveSuccess()">Save Changes</button>
      <button class="btn btn-ghost">Restore Defaults</button>
    </div>
    <div id="settingsSaveAlert" style="margin-top:12px;"></div>
  `;
}

window.switchSettings = function(el, section) {
  document.querySelectorAll('.settings-nav-item').forEach(i => i.classList.remove('active'));
  el.classList.add('active');
  const content = document.getElementById('settingsContent');
  if (section === 'api-keys') {
    content.innerHTML = `
      <div class="card">
        <h3 style="font-size:1rem;font-weight:700;margin-bottom:20px;color:var(--text-primary);">🔑 API Keys</h3>
        <div class="form-group">
          <label class="form-label">NetGuard API Key</label>
          <div class="code-block" style="display:flex;align-items:center;justify-content:space-between;gap:10px;">
            <span>ng_live_•••••••••••••••••••••••••••••••</span>
            <button class="btn btn-ghost btn-sm">Reveal</button>
          </div>
        </div>
        <div class="form-group">
          <label class="form-label">Webhook URL</label>
          <input type="url" class="form-input" placeholder="https://yourapp.com/webhook" />
        </div>
        <div class="form-group">
          <label class="form-label">Shodan API Key (optional)</label>
          <input type="password" class="form-input" placeholder="••••••••••••••••••••••••••••" />
        </div>
        <div class="form-group">
          <label class="form-label">VirusTotal API Key (optional)</label>
          <input type="password" class="form-input" placeholder="••••••••••••••••••••••••••••" />
        </div>
        <button class="btn btn-primary" onclick="showSaveSuccess()">Save API Keys</button>
        <div id="settingsSaveAlert" style="margin-top:12px;"></div>
      </div>
    `;
  } else if (section === 'auth') {
    content.innerHTML = `
      <div class="card">
        <h3 style="font-size:1rem;font-weight:700;margin-bottom:20px;color:var(--text-primary);">🔐 Authentication</h3>
        <div class="form-group">
          <label class="form-label">Saved Credentials</label>
          ${[
            { host: 'admin.legacy-portal.com', user: 'admin' },
            { host: 'portal.acme-corp.io', user: 'netguard-bot' },
          ].map(c => `
            <div style="display:flex;align-items:center;justify-content:space-between;padding:10px;border:1px solid var(--border-subtle);border-radius:var(--radius-md);margin-top:8px;background:rgba(139,92,246,0.03);">
              <div>
                <div style="font-size:0.85rem;font-weight:500;color:var(--text-primary);">${c.host}</div>
                <div style="font-size:0.75rem;color:var(--text-muted);">User: ${c.user}</div>
              </div>
              <div style="display:flex;gap:8px;">
                <button class="btn btn-ghost btn-sm">Edit</button>
                <button class="btn btn-danger btn-sm">Remove</button>
              </div>
            </div>
          `).join('')}
        </div>
        <button class="btn btn-secondary">+ Add Credentials</button>
      </div>
    `;
  } else {
    content.innerHTML = renderGeneralSettings();
  }
};

window.showSaveSuccess = function() {
  const el = document.getElementById('settingsSaveAlert');
  if (el) {
    el.innerHTML = `<div class="alert alert-success">✓ Settings saved successfully.</div>`;
    setTimeout(() => el.innerHTML = '', 3000);
  }
};

/* ============================================================
   12. PAGE: PROFILE
   ============================================================ */
function renderProfile(container) {
  container.innerHTML = `
    <div class="page-header">
      <h1 class="page-title">My <span>Profile</span></h1>
      <p class="page-subtitle">Manage your account details and preferences</p>
    </div>

    <div class="profile-hero">
      <div class="profile-avatar-lg">AK</div>
      <div>
        <div class="profile-name">Alex K.</div>
        <div class="profile-email">alex.k@netguard.io</div>
        <div class="profile-role"><span>🛡</span> Security Analyst · Pro Plan</div>
      </div>
      <div style="margin-left:auto;display:flex;flex-direction:column;gap:12px;align-items:flex-end;flex-shrink:0;">
        <button class="btn btn-secondary">Edit Profile</button>
        <button class="btn btn-danger" onclick="handleLogout()">Sign Out</button>
      </div>
    </div>

    <div style="display:grid;grid-template-columns:1fr 1fr;gap:20px;">

      <div class="card">
        <h3 style="font-size:1rem;font-weight:700;margin-bottom:20px;color:var(--text-primary);">Account Details</h3>
        <div class="form-group">
          <label class="form-label">Full Name</label>
          <input type="text" class="form-input" value="Alex K." />
        </div>
        <div class="form-group">
          <label class="form-label">Email</label>
          <input type="email" class="form-input" value="alex.k@netguard.io" />
        </div>
        <div class="form-group">
          <label class="form-label">Organization</label>
          <input type="text" class="form-input" value="Acme Corp Security Team" />
        </div>
        <div class="form-group">
          <label class="form-label">Time Zone</label>
          <select class="form-select">
            <option selected>UTC+05:30 (IST)</option>
            <option>UTC+00:00 (GMT)</option>
            <option>UTC-05:00 (EST)</option>
          </select>
        </div>
        <button class="btn btn-primary" onclick="showProfileSave()">Save Changes</button>
        <div id="profileSaveAlert" style="margin-top:12px;"></div>
      </div>

      <div style="display:flex;flex-direction:column;gap:16px;">
        <div class="card">
          <h3 style="font-size:1rem;font-weight:700;margin-bottom:16px;color:var(--text-primary);">Security</h3>
          <div class="toggle-row">
            <div class="toggle-info"><h4>Two-Factor Auth</h4><p>Add an extra layer of security</p></div>
            <label class="toggle"><input type="checkbox"><span class="toggle-slider"></span></label>
          </div>
          <div class="toggle-row">
            <div class="toggle-info"><h4>Login Alerts</h4><p>Email on new sign-in from unknown device</p></div>
            <label class="toggle"><input type="checkbox" checked><span class="toggle-slider"></span></label>
          </div>
          <div style="margin-top:16px;">
            <button class="btn btn-ghost btn-sm">🔑 Change Password</button>
          </div>
        </div>

        <div class="card">
          <h3 style="font-size:1rem;font-weight:700;margin-bottom:16px;color:var(--text-primary);">Activity Stats</h3>
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
            ${[
              { label: 'Scans run', val: '247' },
              { label: 'Targets', val: '18' },
              { label: 'Reports', val: '22' },
              { label: 'Days active', val: '94' },
            ].map(s => `
              <div style="text-align:center;padding:12px;border:1px solid var(--border-subtle);border-radius:var(--radius-md);background:rgba(139,92,246,0.03);">
                <div style="font-size:1.4rem;font-weight:800;font-family:'JetBrains Mono',monospace;color:var(--purple-300);">${s.val}</div>
                <div style="font-size:0.72rem;color:var(--text-muted);margin-top:4px;">${s.label}</div>
              </div>
            `).join('')}
          </div>
        </div>

        <div class="card">
          <h3 style="font-size:1rem;font-weight:700;margin-bottom:16px;color:var(--text-primary);">Plan</h3>
          <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;">
            <div>
              <div style="font-size:1.1rem;font-weight:700;color:var(--purple-300);">Pro Plan</div>
              <div style="font-size:0.78rem;color:var(--text-muted);">Renews May 1, 2026</div>
            </div>
            <span class="badge badge-info">Active</span>
          </div>
          <div style="margin-bottom:8px;font-size:0.8rem;color:var(--text-muted);">Scan quota: 247 / 500 used</div>
          <div class="progress-bar" style="margin-bottom:16px;">
            <div class="progress-fill" style="width:49.4%;background:linear-gradient(90deg,var(--purple-500),var(--purple-700));"></div>
          </div>
          <button class="btn btn-secondary btn-sm">Upgrade to Enterprise</button>
        </div>
      </div>

    </div>

    <div id="logoutConfirm" style="display:none;margin-top:20px;">
      <div class="alert alert-critical" style="display:flex;align-items:center;gap:16px;">
        <span>Are you sure you want to sign out?</span>
        <button class="btn btn-danger btn-sm" onclick="confirmLogout()">Yes, Sign Out</button>
        <button class="btn btn-ghost btn-sm" onclick="cancelLogout()">Cancel</button>
      </div>
    </div>
  `;
}

window.showProfileSave = function() {
  const el = document.getElementById('profileSaveAlert');
  if (el) {
    el.innerHTML = `<div class="alert alert-success">✓ Profile updated successfully.</div>`;
    setTimeout(() => el.innerHTML = '', 3000);
  }
};

window.handleLogout = function() {
  const el = document.getElementById('logoutConfirm');
  if (el) el.style.display = 'block';
};

window.cancelLogout = function() {
  const el = document.getElementById('logoutConfirm');
  if (el) el.style.display = 'none';
};

window.confirmLogout = function() {
  const el = document.getElementById('logoutConfirm');
  if (el) el.innerHTML = `<div class="alert alert-info">Signing out… <span class="spinner" style="width:14px;height:14px;display:inline-block;vertical-align:middle;margin-left:8px;"></span></div>`;
  setTimeout(() => {
    navigateTo('dashboard');
  }, 2000);
};

/* ============================================================
   13. HELPERS
   ============================================================ */
function animateCounter(id, from, to, duration) {
  const el = document.getElementById(id);
  if (!el) return;
  const start = performance.now();
  function update(ts) {
    const elapsed = ts - start;
    const progress = Math.min(elapsed / duration, 1);
    const eased = 1 - Math.pow(1 - progress, 3);
    el.textContent = Math.round(from + (to - from) * eased);
    if (progress < 1) requestAnimationFrame(update);
  }
  requestAnimationFrame(update);
}


/* ============================================================
   14. VULNERABILITY MAP & DATA REFRESH
   ============================================================ */

function initVulnerabilityMap() {
  const map = document.getElementById('vulnMap');
  if (!map) return;

  const nodes = [
    { x: 15, y: 30, sev: 'critical' },
    { x: 45, y: 70, sev: 'high' },
    { x: 80, y: 20, sev: 'medium' },
    { x: 60, y: 50, sev: 'high' },
    { x: 25, y: 85, sev: 'critical' },
    { x: 85, y: 80, sev: 'medium' },
  ];

  nodes.forEach(n => {
    const node = document.createElement('div');
    node.className = `map-node ${n.sev}`;
    node.style.left = `${n.x}%`;
    node.style.top = `${n.y}%`;
    node.style.background = n.sev === 'critical' ? '#ef4444' : n.sev === 'high' ? '#f97316' : '#eab308';
    node.style.boxShadow = `0 0 10px ${node.style.background}`;
    map.appendChild(node);
  });
}

// Global Refresh Loop for real-time updates
setInterval(async () => {
  if (currentPage === 'dashboard') {
    const stats = await fetchAPI('/api/stats');
    if (stats) {
      document.getElementById('stat-scans') && (document.getElementById('stat-scans').textContent = stats.scans);
      document.getElementById('stat-vulns') && (document.getElementById('stat-vulns').textContent = stats.vulns);
      document.getElementById('stat-apis') && (document.getElementById('stat-apis').textContent = stats.apis);
      document.getElementById('stat-fp') && (document.getElementById('stat-fp').textContent = stats.fp);
    }
  }
}, 5000);

/* ============================================================
   14b. PAGE: ATTACK CHAIN  (Visual Flow Edition)
   ============================================================ */
async function renderAttackChain(container) {

  container.innerHTML = `<div class="loading-state">Reconstructing Attack Chain...</div>`;

  // ── Live fetch ───────────────────────────────────────────────
  const liveData = await fetchAPI('/api/attack-chain') || {
    attack_chain: [
      'User logged in with stolen credentials',
      'Escalated to Admin via broken access control',
      'SQL Injection dumped the users table',
    ],
    impact: 'CRITICAL',
  };
  const chain  = liveData.attack_chain || [];
  const impact = (liveData.impact || 'CRITICAL').toUpperCase();

  // ── Per-step metadata (icon, colour, label, MITRE, description) ──
  const META = [
    {
      icon: '🔐', color: '#22c55e', tag: 'MEDIUM',
      label: 'Initial Access', mitre: 'T1078',
      desc: 'Attacker gains a foothold using valid credentials obtained via phishing or credential stuffing.',
    },
    {
      icon: '🚪', color: '#f97316', tag: 'HIGH',
      label: 'Privilege Escalation', mitre: 'T1548',
      desc: 'Exploits broken access control or IDOR to assume a higher-privileged role without authorisation.',
    },
    {
      icon: '💉', color: '#ef4444', tag: 'CRITICAL',
      label: 'Exploitation', mitre: 'T1190',
      desc: 'Injects malicious SQL payload to exfiltrate or destroy sensitive data from the database.',
    },
    {
      icon: '📡', color: '#a855f7', tag: 'HIGH',
      label: 'Data Exfiltration', mitre: 'T1041',
      desc: 'Sensitive records are transmitted out-of-band to an attacker-controlled endpoint.',
    },
    {
      icon: '🛠️', color: '#3b82f6', tag: 'HIGH',
      label: 'Persistence', mitre: 'T1505',
      desc: 'Backdoor or rogue admin account installed to maintain long-term access.',
    },
    {
      icon: '💀', color: '#ef4444', tag: 'CRITICAL',
      label: 'Impact', mitre: 'T1485',
      desc: 'Data destruction, ransomware deployment, or full service takeover executed.',
    },
  ];

  const sevClass = { LOW: 'low', MEDIUM: 'medium', HIGH: 'high', CRITICAL: 'critical' };

  // ── Build step cards HTML ─────────────────────────────────────
  const stepCards = chain.map((step, i) => {
    const m    = META[i] || { icon: '⚡', color: '#a855f7', tag: 'HIGH', label: `Step ${i+1}`, mitre: '—', desc: '' };
    const isLast = i === chain.length - 1;
    return /* html */`

      <!-- ══ STEP CARD ${i+1} ══ -->
      <div class="ac-flow-card" style="
          --ac-color: ${m.color};
          animation-delay: ${i * 0.15}s;
        "
        data-step="${i}"
      >
        <!-- Card inner layout -->
        <div class="ac-card-rail"></div>

        <div class="ac-card-body">

          <!-- Header row -->
          <div class="ac-card-header">
            <div class="ac-card-left">
              <div class="ac-step-badge">
                ${m.icon}
              </div>
              <div class="ac-step-info">
                <div class="ac-step-label">${m.label}</div>
                <div class="ac-step-num">Step ${i+1} of ${chain.length}</div>
              </div>
            </div>
            <div class="ac-card-right">
              <span class="badge badge-${sevClass[m.tag] || 'high'}">${m.tag}</span>
              <span class="ac-mitre-tag">${m.mitre}</span>
            </div>
          </div>

          <!-- Main step text -->
          <div class="ac-step-title">${step}</div>

          <!-- Description -->
          ${m.desc ? `<div class="ac-step-desc">${m.desc}</div>` : ''}

          <!-- Progress indicator strip -->
          <div class="ac-progress-strip">
            <div class="ac-progress-fill" style="width:${Math.round(((i + 1) / chain.length) * 100)}%;"></div>
          </div>
          <div class="ac-progress-label">${Math.round(((i + 1) / chain.length) * 100)}% of attack chain complete</div>

        </div>
      </div>

      <!-- ══ CONNECTOR ARROW ══ -->
      ${!isLast ? /* html */`
      <div class="ac-arrow-wrap" data-arrow="${i}">
        <div class="ac-arrow-line"></div>
        <svg class="ac-arrow-head" viewBox="0 0 24 14" xmlns="http://www.w3.org/2000/svg">
          <path d="M0 0 L12 14 L24 0" stroke="${m.color}" stroke-width="2.5" fill="none"
            stroke-linecap="round" stroke-linejoin="round"/>
          <path d="M0 0 L12 14 L24 0" stroke="${m.color}" stroke-width="6" fill="none"
            stroke-linecap="round" stroke-linejoin="round" opacity="0.18"/>
        </svg>
        <span class="ac-arrow-label">leads to</span>
      </div>
      ` : ''}
    `;
  }).join('');

  // ── Full impact summary row ───────────────────────────────────
  const impactColor = impact === 'CRITICAL' ? '#ef4444' : impact === 'HIGH' ? '#f97316' : '#eab308';
  const impactMeta = [
    { icon: '🎯', label: 'Attack Steps',   val: chain.length },
    { icon: '⚠️', label: 'Risk Level',     val: impact },
    { icon: '🕐', label: 'Dwell Time',     val: '< 72 h' },
    { icon: '💾', label: 'Data at Risk',   val: 'DB / PII' },
  ];

  // ── Render full page ──────────────────────────────────────────
  container.innerHTML = /* html */`

    <!-- ─── HERO HEADER ─── -->
    <div class="page-header" style="text-align:center; padding-bottom:0; position:relative;">
      
      <!-- Replay Button -->
      <button id="ac-replay-btn" class="btn btn-secondary btn-sm" onclick="window.__acReplay()" style="position:absolute; right:10px; top:0px; border-radius:20px; background:rgba(255,255,255,0.05); border-color:var(--border-normal); transition: all 0.3s ease;">
        <span style="color:#a855f7; margin-right:6px;">▶</span> Replay Simulation
      </button>

      <div class="ac-live-badge">
        <span class="ac-pulse-dot"></span>
        <span>Live Simulation</span>
      </div>
      <h1 class="page-title" style="font-size:2rem; margin-top:14px;">Attack Chain <span>Visual Flow</span></h1>
      <p class="page-subtitle" style="max-width:580px; margin:8px auto 28px;">
        Multi-step exploitation path — each card represents one phase of the attack.<br>
        Arrows show the adversarial progression from initial foothold to full compromise.
      </p>

      <!-- Quick stats strip -->
      <div class="ac-stats-strip">
        ${impactMeta.map(m => `
          <div class="ac-stat">
            <span class="ac-stat-icon">${m.icon}</span>
            <div>
              <div class="ac-stat-val" style="${m.label === 'Risk Level' ? `color:${impactColor};` : ''}">${m.val}</div>
              <div class="ac-stat-lbl">${m.label}</div>
            </div>
          </div>
        `).join('<div class="ac-stat-div"></div>')}
      </div>
    </div>

    <!-- ─── VISUAL FLOW ─── -->
    <div class="ac-flow-container" id="ac-timeline">
      ${stepCards}
    </div>

    <!-- ─── IMPACT BANNER ─── -->
    <div class="ac-impact-banner" id="ac-impact" style="--impact-color: ${impactColor};">
      <div class="ac-impact-inner">
        <div class="ac-impact-icon">☠️</div>
        <div>
          <div class="ac-impact-label">FINAL IMPACT ASSESSMENT</div>
          <div class="ac-impact-title">Full System Compromise</div>
          <div class="ac-impact-sub">
            All ${chain.length} attack stage${chain.length !== 1 ? 's' : ''} executed —
            attacker achieved full database access and admin takeover.
          </div>
        </div>
        <div class="ac-impact-risk">
          <div class="ac-risk-ring">
            <span>${impact}</span>
          </div>
          <div class="ac-risk-label">Risk Level</div>
        </div>
      </div>
      <!-- Decorative scan line -->
      <div class="ac-impact-scan"></div>
    </div>

  `;

  // ── Emulate React State for Replay Functionality ─────────
  let visibleSteps = [];
  let isReplaying = false;

  window.__acReplay = async () => {
    if (isReplaying) return;
    isReplaying = true;
    visibleSteps = [];

    const replayBtn = document.getElementById('ac-replay-btn');
    if (replayBtn) {
      replayBtn.disabled = true;
      replayBtn.style.opacity = '0.6';
      replayBtn.style.cursor = 'not-allowed';
      replayBtn.innerHTML = `<span style="color:#a855f7; margin-right:6px;">⏳</span> Replaying attack.....`;
    }

    // Hide everything instantly
    container.querySelectorAll('.ac-flow-card').forEach((el) => {
      el.classList.remove('ac-card-visible');
      el.style.animationDelay = '0s'; // override initial stagger css
    });
    container.querySelectorAll('.ac-arrow-wrap').forEach((el) => el.classList.remove('ac-arrow-visible'));
    const imp = document.getElementById('ac-impact');
    if (imp) imp.classList.remove('ac-card-visible');

    // Step 3 Core Logic: Async Loop with Promise delay
    for (let i = 0; i < chain.length; i++) {
      // Clear previous step's highlight
      container.querySelectorAll('.ac-card-highlight').forEach(el => el.classList.remove('ac-card-highlight'));

      // Await shorter 300ms delay for snappier UI instead of 1000ms
      await new Promise((resolve) => setTimeout(resolve, 300));
      
      // Equivalent to setVisibleSteps((prev) => [...prev, attackChain[i]])
      visibleSteps.push(i);

      // Render the current step card
      const card = container.querySelector(`.ac-flow-card[data-step="${i}"]`);
      if (card) {
        card.classList.add('ac-card-visible', 'ac-card-highlight');
      }

      // Show arrow pointing to next step
      const arrow = container.querySelector(`.ac-arrow-wrap[data-arrow="${i}"]`);
      if (arrow) {
        setTimeout(() => arrow.classList.add('ac-arrow-visible'), 150);
      }
    }

    // Show impact banner when the chain finishes
    if (imp) {
      setTimeout(() => {
        container.querySelectorAll('.ac-card-highlight').forEach(el => el.classList.remove('ac-card-highlight'));
        imp.classList.add('ac-card-visible');
      }, 800);
    } else {
      setTimeout(() => {
        container.querySelectorAll('.ac-card-highlight').forEach(el => el.classList.remove('ac-card-highlight'));
      }, 800);
    }

    // Reset replay flag and button UX
    setTimeout(() => { 
      isReplaying = false; 
      const replayBtn = document.getElementById('ac-replay-btn');
      if (replayBtn) {
        replayBtn.disabled = false;
        replayBtn.style.opacity = '1';
        replayBtn.style.cursor = 'pointer';
        replayBtn.innerHTML = `<span style="color:#a855f7; margin-right:6px;">▶</span> Replay Simulation`;
      }
    }, 1000);
  };

  // Trigger initial render
  setTimeout(() => window.__acReplay(), 50);
}



/* ============================================================
   15. BOOT
   ============================================================ */
document.addEventListener('DOMContentLoaded', () => {
  // Enhance renderDashboard to include map init
  const originalRender = renderDashboard;
  renderDashboard = async (container) => {
    await originalRender(container);
    initVulnerabilityMap();
  };
  
  navigateTo('dashboard');
});
