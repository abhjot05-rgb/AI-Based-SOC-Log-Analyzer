/* Dashboard: loads /api/stats and draws cards, charts and tables. */
(function () {
  'use strict';

  const { $, esc, num, api, sevBadge, statusBadge, showStatus, hideStatus, SEVERITY_COLORS } = window.SOC;

  const SEVERITIES = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];       // stacking order, bottom to top
  const PALETTE = ['#58a6ff', '#f85149', '#d29922', '#3fb950', '#a371f7', '#f0883e', '#39c5cf', '#db61a2'];
  const ALLOWED_EXTENSIONS = ['csv', 'json', 'log', 'txt'];
  const MAX_UPLOAD_BYTES = 10 * 1024 * 1024;

  const chartsReady = typeof window.Chart !== 'undefined';
  if (chartsReady) {
    Chart.defaults.color = '#9da7b3';
    Chart.defaults.borderColor = '#30363d';
    Chart.defaults.font.family = '"Segoe UI", system-ui, Arial, sans-serif';
  }

  let timelineChart = null;
  let distChart = null;
  let busy = false;

  // ---------------------------------------------------------------- helpers
  function statsUrl() {
    const id = $('scopeSelect').value;
    return '/api/stats' + (id ? '?upload_id=' + encodeURIComponent(id) : '');
  }

  function percent(value, max) {
    const v = Number(value), m = Number(max);
    if (!Number.isFinite(v) || !Number.isFinite(m) || m <= 0) return 0;
    return Math.max(0, Math.min(100, (v / m) * 100));
  }

  // Bar widths are set through the DOM (not inline HTML) so the CSP stays strict.
  function applyWidths(container) {
    container.querySelectorAll('[data-w]').forEach(function (el) {
      el.style.width = el.dataset.w + '%';
    });
  }

  function setEmpty(canvasId, emptyId, isEmpty) {
    $(canvasId).classList.toggle('d-none', isEmpty);
    const box = $(emptyId);
    box.classList.toggle('d-none', !isEmpty);
    if (isEmpty && !chartsReady) {
      box.textContent = 'Chart library not loaded. Check your internet connection (or see "Offline use" in the Stage 9 notes).';
    }
  }

  // ---------------------------------------------------------------- rendering
  function renderCards(s) {
    const c = s.severity_counts || {};
    const values = {
      total_logs: s.total_logs, total_alerts: s.total_alerts, anomalies: s.anomalies,
      critical: c.CRITICAL, high: c.HIGH, medium: c.MEDIUM, low: c.LOW
    };
    Object.keys(values).forEach(function (key) { $('stat-' + key).textContent = num(values[key]); });
    $('emptyState').classList.toggle('d-none', s.total_logs > 0);
  }

  function bucketLabel(bucket, kind) {
    // hour bucket: "2026-01-14 03"  ->  "01-14 03:00"
    return kind === 'hour' ? bucket.slice(5, 10) + ' ' + bucket.slice(11) + ':00' : bucket;
  }

  function renderTimeline(timeline) {
    const points = (timeline && timeline.points) || [];
    setEmpty('timelineChart', 'timelineEmpty', points.length === 0 || !chartsReady);
    if (timelineChart) { timelineChart.destroy(); timelineChart = null; }
    if (points.length === 0 || !chartsReady) return;

    timelineChart = new Chart($('timelineChart'), {
      type: 'bar',
      data: {
        labels: points.map(function (p) { return bucketLabel(p.bucket, timeline.bucket); }),
        datasets: SEVERITIES.map(function (sev) {
          return {
            label: sev,
            data: points.map(function (p) { return p[sev] || 0; }),
            backgroundColor: SEVERITY_COLORS[sev],
            borderWidth: 0
          };
        })
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { position: 'bottom' } },
        scales: {
          x: { stacked: true, grid: { display: false } },
          y: { stacked: true, beginAtZero: true, ticks: { precision: 0 } }
        }
      }
    });
  }

  function renderDistribution(threatTypes) {
    const items = threatTypes || [];
    setEmpty('distChart', 'distEmpty', items.length === 0 || !chartsReady);
    if (distChart) { distChart.destroy(); distChart = null; }
    if (items.length === 0 || !chartsReady) return;

    distChart = new Chart($('distChart'), {
      type: 'doughnut',
      data: {
        labels: items.map(function (t) { return t.threat_type; }),
        datasets: [{
          data: items.map(function (t) { return t.count; }),
          backgroundColor: items.map(function (_t, i) { return PALETTE[i % PALETTE.length]; }),
          borderColor: '#161b22',
          borderWidth: 2
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: '58%',
        plugins: { legend: { position: 'bottom' } }
      }
    });
  }

  function renderTopIps(items) {
    const body = $('topIpsBody');
    if (!items || items.length === 0) {
      body.innerHTML = '<tr><td colspan="3" class="text-secondary">No suspicious IPs yet.</td></tr>';
      return;
    }
    body.innerHTML = items.map(function (row) {
      return '<tr><td><code>' + esc(row.source_ip) + '</code></td>' +
        '<td>' + num(row.alerts) + '</td>' +
        '<td><span class="score-bar"><span data-w="' + percent(row.max_score, 100) + '"></span></span>' +
        '<small>' + esc(Math.round(Number(row.max_score) || 0)) + '</small></td></tr>';
    }).join('');
    applyWidths(body);
  }

  function renderThreatTypes(items) {
    const list = $('threatTypesList');
    if (!items || items.length === 0) {
      list.innerHTML = '<li class="text-secondary">No threats detected yet.</li>';
      return;
    }
    const max = Math.max.apply(null, items.map(function (t) { return t.count; }));
    list.innerHTML = items.map(function (t) {
      return '<li class="threat-row"><div class="d-flex justify-content-between">' +
        '<span>' + esc(t.threat_type) + '</span><strong>' + num(t.count) + '</strong></div>' +
        '<span class="score-bar score-bar-wide"><span data-w="' + percent(t.count, max) + '"></span></span></li>';
    }).join('');
    applyWidths(list);
  }

  function renderRecent(items) {
    const body = $('recentAlertsBody');
    if (!items || items.length === 0) {
      body.innerHTML = '<tr><td colspan="8" class="text-secondary">No alerts yet.</td></tr>';
      return;
    }
    body.innerHTML = items.map(function (a) {
      return '<tr>' +
        '<td><a href="/alerts/' + encodeURIComponent(a.id) + '">#' + esc(a.id) + '</a></td>' +
        '<td class="text-nowrap">' + esc(a.timestamp) + '</td>' +
        '<td>' + esc(a.threat_type) + '</td>' +
        '<td>' + sevBadge(a.severity) + '</td>' +
        '<td>' + esc(Math.round(Number(a.threat_score) || 0)) + '</td>' +
        '<td><code>' + esc(a.source_ip || '-') + '</code></td>' +
        '<td>' + esc(a.username || '-') + '</td>' +
        '<td>' + statusBadge(a.status) + '</td></tr>';
    }).join('');
  }

  // ---------------------------------------------------------------- loading
  async function loadUploads(selectId) {
    const data = await api('/api/uploads');
    const select = $('scopeSelect');
    const wanted = selectId !== undefined ? String(selectId) : select.value;

    select.textContent = '';
    const all = document.createElement('option');
    all.value = '';
    all.textContent = 'All uploads';
    select.appendChild(all);

    data.items.forEach(function (u) {
      const opt = document.createElement('option');
      opt.value = String(u.id);
      opt.textContent = '#' + u.id + '  ' + u.original_name + '  (' + (u.total_alerts || 0) + ' alerts)';
      select.appendChild(opt);
    });

    const exists = Array.prototype.some.call(select.options, function (o) { return o.value === wanted; });
    select.value = exists ? wanted : '';
    $('deleteBtn').disabled = busy || !select.value;
  }

  async function loadStats() {
    const s = await api(statsUrl());
    renderCards(s);
    renderTimeline(s.timeline);
    renderDistribution(s.threat_types);
    renderTopIps(s.top_ips);
    renderThreatTypes(s.threat_types);
    renderRecent(s.recent_alerts);
    $('lastUpdated').textContent = 'Updated ' + new Date().toLocaleTimeString();
  }

  async function refreshAll(selectId) {
    await loadUploads(selectId);
    await loadStats();
  }

  // ---------------------------------------------------------------- actions
  function setBusy(flag) {
    busy = flag;
    ['uploadBtn', 'demoBtn', 'refreshBtn'].forEach(function (id) { $(id).disabled = flag; });
    $('deleteBtn').disabled = flag || !$('scopeSelect').value;
  }

  function summarize(result) {
    const a = result.analysis;
    return result.filename + ': ' + num(a.total_logs) + ' logs, ' + num(a.total_alerts) + ' alerts, ' +
      num(a.anomaly_count) + ' ML anomalies' +
      (a.ml_trained ? '' : ' (ML skipped: not enough events)') + '.';
  }

  async function runTask(workingMessage, task, successMessage) {
    if (busy) return;
    setBusy(true);
    showStatus($('statusBox'), 'info', workingMessage);
    try {
      const result = await task();
      await refreshAll(result && result.upload_id !== undefined ? result.upload_id : '');
      showStatus($('statusBox'), 'success', successMessage(result));
    } catch (err) {
      showStatus($('statusBox'), 'danger', err.message);
    } finally {
      setBusy(false);
    }
  }

  function uploadFile() {
    const input = $('fileInput');
    const file = input.files[0];
    const box = $('statusBox');
    if (!file) return showStatus(box, 'warning', 'Choose a log file first.');
    const ext = file.name.indexOf('.') >= 0 ? file.name.split('.').pop().toLowerCase() : '';
    if (ALLOWED_EXTENSIONS.indexOf(ext) < 0) {
      return showStatus(box, 'warning', 'File type not allowed. Use: ' + ALLOWED_EXTENSIONS.join(', ') + '.');
    }
    if (file.size > MAX_UPLOAD_BYTES) return showStatus(box, 'warning', 'File is larger than 10 MB.');

    const form = new FormData();
    form.append('file', file);
    runTask('Uploading and analyzing...', async function () {
      const result = await api('/api/upload', { method: 'POST', body: form });
      input.value = '';
      return result;
    }, summarize);
  }

  function generateDemo() {
    runTask('Generating demo data and analyzing...', function () {
      return api('/api/generate-sample', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ kind: $('demoKind').value })
      });
    }, summarize);
  }

  function deleteSelected() {
    const id = $('scopeSelect').value;
    if (!id) return;
    if (!window.confirm('Delete upload #' + id + ' with all its logs and alerts? This cannot be undone.')) return;
    runTask('Deleting...', async function () {
      await api('/api/uploads/' + encodeURIComponent(id), { method: 'DELETE' });
      return { upload_id: '' };
    }, function () { return 'Upload #' + id + ' deleted.'; });
  }

  // ---------------------------------------------------------------- start
  $('uploadBtn').addEventListener('click', uploadFile);
  $('demoBtn').addEventListener('click', generateDemo);
  $('deleteBtn').addEventListener('click', deleteSelected);
  $('refreshBtn').addEventListener('click', function () {
    refreshAll().then(function () { hideStatus($('statusBox')); })
      .catch(function (err) { showStatus($('statusBox'), 'danger', err.message); });
  });
  $('scopeSelect').addEventListener('change', function () {
    $('deleteBtn').disabled = busy || !$('scopeSelect').value;
    loadStats().catch(function (err) { showStatus($('statusBox'), 'danger', err.message); });
  });

  refreshAll().catch(function (err) { showStatus($('statusBox'), 'danger', err.message); });
})();