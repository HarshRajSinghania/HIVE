/* ═══════════════════════════════════════════════════════════════════════
   hive.js  —  HIVE Command Center  ·  Client-side Behaviors
   ═══════════════════════════════════════════════════════════════════════ */

// ── Cytoscape.js Styling ──────────────────────────────────────────────────

function hiveCyStyle() {
  return [
    {
      selector: 'node[type="device"]',
      style: {
        'background-color': 'data(color)',
        'border-width': 2,
        'border-color': 'data(border)',
        'label': 'data(label)',
        'color': '#c9d1d9',
        'font-size': 11,
        'text-valign': 'bottom',
        'text-margin-y': 6,
        'shape': 'round-rectangle',
        'width': 100,
        'height': 36,
        'text-wrap': 'ellipsis',
        'text-max-width': 96,
        'overlay-opacity': 0,
      }
    },
    {
      selector: 'node[type="entity"]',
      style: {
        'background-color': 'data(color)',
        'label': 'data(label)',
        'color': '#c9d1d9',
        'font-size': 10,
        'text-valign': 'bottom',
        'text-margin-y': 4,
        'shape': 'ellipse',
        'width': 'mapData(device_count, 2, 10, 28, 60)',
        'height': 'mapData(device_count, 2, 10, 28, 60)',
        'overlay-opacity': 0,
      }
    },
    {
      selector: 'edge',
      style: {
        'line-color': 'data(color)',
        'width': 'data(width)',
        'opacity': 0.8,
        'curve-style': 'bezier',
        'label': '',
        'overlay-opacity': 0,
      }
    },
    {
      selector: 'node:selected',
      style: {
        'border-width': 3,
        'border-color': '#00d4aa',
        'background-color': '#1f3d35',
        'overlay-padding': 6,
      }
    },
    {
      selector: 'edge:selected',
      style: {
        'line-color': '#00d4aa',
        'width': 4,
        'overlay-padding': 3,
      }
    },
    {
      selector: 'node:active',
      style: {
        'overlay-opacity': 0.15,
        'overlay-color': '#00d4aa',
        'overlay-padding': 8,
      }
    },
  ];
}

// ── Graph Loading ─────────────────────────────────────────────────────────

async function loadGraphData(caseId, mode, minScore, deviceFilter) {
  const url = `/api/graph/data?case_id=${encodeURIComponent(caseId)}&mode=${mode}&min_score=${minScore}` +
              (deviceFilter ? `&device_id=${encodeURIComponent(deviceFilter)}` : '');
  try {
    const res = await fetch(url);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } catch (err) {
    console.error('Graph data fetch failed:', err);
    return { elements: { nodes: [], edges: [] } };
  }
}

// ── Graph Initialization ──────────────────────────────────────────────────

function initCytoscape(containerId, elements) {
  if (window.cy) window.cy.destroy();
  
  window.cy = cytoscape({
    container: document.getElementById(containerId),
    elements: elements,
    style: hiveCyStyle(),
    layout: {
      name: 'cose',
      animate: true,
      randomize: true,
      nodeRepulsion: 8000,
      idealEdgeLength: 120,
      edgeElasticity: 200,
      gravity: 0.25,
      numIter: 500,
    },
    minZoom: 0.1,
    maxZoom: 4,
    wheelSensitivity: 0.1,
  });

  // Pan / zoom with mouse
  window.cy.on('tap', 'node', function(evt) {
    if (window.showNodeInfo) window.showNodeInfo(evt.target);
  });
  window.cy.on('tap', 'edge', function(evt) {
    if (window.showEdgeInfo) window.showEdgeInfo(evt.target);
  });
  window.cy.on('tap', function(evt) {
    if (evt.target === window.cy) {
      const panel = document.getElementById('cy-info');
      if (panel) panel.style.display = 'none';
    }
  });

  return window.cy;
}

// ── Table Row Click Handlers ──────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', function() {
  // Clickable rows with data-href
  document.querySelectorAll('.clickable-row[data-href]').forEach(row => {
    row.style.cursor = 'pointer';
    row.addEventListener('click', function(e) {
      if (!e.target.closest('a, button')) {
        window.location.href = this.dataset.href;
      }
    });
  });

  // Search overlay
  const searchInput = document.getElementById('topbar-search');
  const searchOverlay = document.getElementById('search-overlay');
  if (searchInput && searchOverlay) {
    searchInput.addEventListener('focus', () => {
      searchOverlay.classList.remove('d-none');
    });
  }
});

// ── Search Utilities ──────────────────────────────────────────────────────

function closeSearch() {
  const results = document.getElementById('topbar-results');
  const overlay = document.getElementById('search-overlay');
  if (results) results.innerHTML = '';
  if (overlay) overlay.classList.add('d-none');
}

document.addEventListener('click', function(e) {
  if (!e.target.closest('.topbar-search')) {
    closeSearch();
  }
});

// ── Form Utilities ────────────────────────────────────────────────────────

function switchCase(caseId) {
  if (caseId) {
    window.location.href = `/case/${encodeURIComponent(caseId)}`;
  }
}

function toggleSidebar() {
  const sidebar = document.getElementById('sidebar');
  const main = document.querySelector('.hive-main');
  if (sidebar && main) {
    sidebar.classList.toggle('collapsed');
    main.classList.toggle('sidebar-collapsed');
  }
}

// ── HTMX Enhancements ─────────────────────────────────────────────────────

document.addEventListener('htmx:beforeRequest', function(evt) {
  const loadingBar = document.getElementById('hive-loading');
  if (loadingBar) loadingBar.classList.add('loading');
});

document.addEventListener('htmx:afterRequest', function(evt) {
  const loadingBar = document.getElementById('hive-loading');
  if (loadingBar) loadingBar.classList.remove('loading');
});

document.addEventListener('htmx:afterSwap', function(evt) {
  // Re-initialize any data attributes after swap
  document.querySelectorAll('.clickable-row[data-href]').forEach(row => {
    if (!row.hasListener) {
      row.style.cursor = 'pointer';
      row.addEventListener('click', function(e) {
        if (!e.target.closest('a, button')) {
          window.location.href = this.dataset.href;
        }
      });
      row.hasListener = true;
    }
  });
});

// ── Keyboard Shortcuts ────────────────────────────────────────────────────

document.addEventListener('keydown', function(e) {
  // Ctrl+/ to focus search
  if ((e.ctrlKey || e.metaKey) && e.key === '/') {
    e.preventDefault();
    const search = document.getElementById('topbar-search');
    if (search) search.focus();
  }
  
  // Esc to close modals and search
  if (e.key === 'Escape') {
    closeSearch();
    const modals = document.querySelectorAll('.modal.show');
    modals.forEach(modal => {
      const bsModal = bootstrap.Modal.getInstance(modal);
      if (bsModal) bsModal.hide();
    });
  }
});

// ── Tooltip / Popover Support ─────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', function() {
  // Initialize Bootstrap tooltips
  document.querySelectorAll('[data-bs-toggle="tooltip"]').forEach(el => {
    new bootstrap.Tooltip(el);
  });
});

// ── AI Chat Utilities ─────────────────────────────────────────────────────

function setAIQuestion(q) {
  const input = document.getElementById('ai-input');
  if (input) {
    input.value = q;
    input.focus();
  }
}

function useAISuggestion(btn) {
  setAIQuestion(btn.textContent.trim());
}

function scrollAIThreadToBottom() {
  const thread = document.getElementById('ai-thread');
  if (thread) {
    thread.scrollTop = thread.scrollHeight;
  }
}

document.addEventListener('htmx:afterSwap', function(evt) {
  if (evt.detail.target.id === 'ai-messages') {
    scrollAIThreadToBottom();
  }
});

// AI input: Ctrl+Enter to submit
const aiInput = document.getElementById('ai-input');
if (aiInput) {
  aiInput.addEventListener('keydown', function(e) {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
      e.preventDefault();
      const form = document.getElementById('ai-form');
      if (form) form.dispatchEvent(new Event('submit', { bubbles: true }));
    }
  });
}

// ── Tab Memory ────────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', function() {
  // Keep current tab in URL hash
  document.querySelectorAll('.nav-link[data-bs-toggle="tab"]').forEach(tab => {
    tab.addEventListener('shown.bs.tab', function(e) {
      history.replaceState(null, null, e.target.getAttribute('href'));
    });
  });

  // Activate tab from URL hash on page load
  const hash = window.location.hash;
  if (hash) {
    const tab = document.querySelector(`.nav-link[href="${hash}"]`);
    if (tab) new bootstrap.Tab(tab).show();
  }
});

// ── Table Sorting (Optional) ──────────────────────────────────────────────

function sortTable(headerEl, columnIndex) {
  const table = headerEl.closest('table');
  if (!table) return;

  const tbody = table.querySelector('tbody');
  if (!tbody) return;

  const rows = Array.from(tbody.querySelectorAll('tr'));
  const isAscending = !headerEl.dataset.sortAsc;

  rows.sort((a, b) => {
    const aVal = a.cells[columnIndex]?.textContent.trim() || '';
    const bVal = b.cells[columnIndex]?.textContent.trim() || '';
    
    const aNum = parseFloat(aVal);
    const bNum = parseFloat(bVal);
    
    if (!isNaN(aNum) && !isNaN(bNum)) {
      return isAscending ? aNum - bNum : bNum - aNum;
    }
    return isAscending ? aVal.localeCompare(bVal) : bVal.localeCompare(aVal);
  });

  rows.forEach(row => tbody.appendChild(row));
  
  headerEl.dataset.sortAsc = isAscending;
  headerEl.classList.toggle('sort-asc', isAscending);
  headerEl.classList.toggle('sort-desc', !isAscending);
}

// ── Modal Enhancements ────────────────────────────────────────────────────

document.addEventListener('show.bs.modal', function(e) {
  // Prevent body scroll when modal is open
  document.body.style.overflow = 'hidden';
});

document.addEventListener('hidden.bs.modal', function(e) {
  document.body.style.overflow = 'auto';
});

// ── Session / CSRF (if needed) ────────────────────────────────────────────

function getCookie(name) {
  const v = `; ${document.cookie}`.split(`; ${name}=`);
  if (v.length === 2) return v.pop().split(';').shift();
  return null;
}

// ── Pagination Helpers ────────────────────────────────────────────────────

function goToPage(pageNum, baseUrl) {
  const url = new URL(baseUrl, window.location.origin);
  url.searchParams.set('page', pageNum);
  window.location.href = url.toString();
}

// ── Format Helpers ────────────────────────────────────────────────────────

function formatTimestamp(ts) {
  if (!ts) return '—';
  try {
    const d = new Date(ts);
    return d.toLocaleString('en-US', {
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: false,
    });
  } catch (e) {
    return ts.replace('T', ' ').replace('Z', '').substring(0, 16);
  }
}

function truncate(text, length = 50) {
  if (!text) return '';
  return text.length > length ? text.substring(0, length - 1) + '…' : text;
}

function scoreToColor(score) {
  const s = parseFloat(score);
  if (isNaN(s)) return 'secondary';
  if (s >= 0.8) return 'danger';
  if (s >= 0.6) return 'warning';
  if (s >= 0.4) return 'info';
  return 'secondary';
}

// ── Export / Download Helpers ─────────────────────────────────────────────

function downloadAsJSON(data, filename = 'hive_export.json') {
  const json = JSON.stringify(data, null, 2);
  const blob = new Blob([json], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

function downloadAsCSV(headers, rows, filename = 'hive_export.csv') {
  const csv = [
    headers.map(h => `"${h}"`).join(','),
    ...rows.map(r => r.map(cell => `"${cell}"`).join(','))
  ].join('\n');
  
  const blob = new Blob([csv], { type: 'text/csv' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

// ── Initialization ────────────────────────────────────────────────────────

console.log('HIVE Command Center v1.0.0 — JavaScript loaded');
