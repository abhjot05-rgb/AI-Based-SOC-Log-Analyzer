/* Threats page: loads /api/threats and fills cards, charts and tables. */
(function () {
  'use strict';

  const { $, esc, num, api, sevBadge, fillUploads, queryString, showStatus, hideStatus,
          SEVERITY_COLORS } = window.SOC;
  const charts = window.SOC.charts;

  const SEVERITIES = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
  const METHOD_COLORS = { 'RULE': '#58a6ff', 'ML': '#a371f7', 'RULE+ME': '#3fb950', 'RULE+ML': '#3fb950' };
  let loadId = 0;

  function scopeId() { return $('scopeSelect').value; }

  // A link to another page that keeps the selected upload (esc() makes it safe inside an attribute)
  function link(path, params) {
    return esc(path + '?' + queryString(Object.assign({}, params, { upload_id: scopeId() })));
  }

  function sevMix(counts) {
    const parts = SEVERITIES.slice().reverse().filter(function (s) { return counts[s] > 0; })
      .map(function (s) {
        return '<span class="sev-badge sev-' + s.toLowerCase() + '">' + s + ' ' + num(counts[s]) + '</span>';
      });
    return parts.length ? parts.join(' ') : '-';
  }

  function renderCards(totals) {
    $('th-types').textContent = num(totals.threat_types);
    $('th-alerts').textContent = num(totals.alerts);
    $('th-ips').textContent = num(totals.unique_ips);
    $('th-compromised').textContent = num(totals.possible_compromises);
  }

  function renderTypeChart(items) {
    charts.draw('typeChart', 'typeEmpty', items.length === 0, function () {
      return {
        type: 'bar',
        data: {
          labels: items.map(function (t) { return t.threat_type; }),
          datasets: SEVERITIES.map(function (s) {
            return {
              label: s,
              data: items.map(function (t) { return t.severity[s] || 0; }),
              backgroundColor: SEVERITY_COLORS[s],
              borderWidth: 0
            };
          })
        },
        options: {
          indexAxis: 'y',
          responsive: true,
          maintainAspectRatio: false,
          plugins: { legend: { position: 'bottom' } },
          scales: {
            x: { stacked: true, beginAtZero: true, ticks: { precision: 0 } },
            y: { stacked: true, grid: { display: false } }
          }
        }
      };
    }, 'No alerts yet');
  }

  function renderMethodChart(methods) {
    const names = Object.keys(methods).filter(function (k) { return methods[k] > 0; });
    charts.draw('methodChart', 'methodEmpty', names.length === 0, function () {
      return {
        type: 'doughnut',
        data: {
          labels: names,
          datasets: [{
            data: names.map(function (k) { return methods[k]; }),
            backgroundColor: names.map(function (k) { return METHOD_COLORS[k] || '#8b949e'; }),
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
      };
    }, 'No alerts yet');
  }

  function renderTypes(items) {
    const body = $('typesBody');
    if (items.length === 0) {
      body.innerHTML = '<tr><td colspan="7" class="text-secondary">No threats detected yet.</td></tr>';
      return;
    }
    body.innerHTML = items.map(function (t) {
      return '<tr>' +
        '<td><a href="' + link('/alerts', { threat_type: t.threat_type }) + '">' + esc(t.threat_type) + '</a></td>' +
        '<td>' + num(t.count) + '</td>' +
        '<td>' + sevMix(t.severity) + '</td>' +
        '<td>' + esc(t.avg_score) + '</td>' +
        '<td>' + esc(Math.round(Number(t.max_score) || 0)) + '</td>' +
        '<td>' + num(t.unique_ips) + '</td>' +
        '<td>' + num(t.events) + '</td></tr>';
    }).join('');
  }

  function renderAttackers(items) {
    const body = $('attackersBody');
    if (items.length === 0) {
      body.innerHTML = '<tr><td colspan="9" class="text-secondary">No source IPs yet.</td></tr>';
      return;
    }
    body.innerHTML = items.map(function (a) {
      const types = a.threat_types.map(function (t) {
        return '<span class="badge text-bg-secondary me-1">' + esc(t) + '</span>';
      }).join('');
      return '<tr>' +
        '<td><code>' + esc(a.source_ip) + '</code></td>' +
        '<td>' + (a.internal ? 'internal' : 'external') + '</td>' +
        '<td>' + num(a.alerts) + '</td>' +
        '<td>' + sevBadge(a.highest_severity) + '</td>' +
        '<td>' + esc(Math.round(Number(a.max_score) || 0)) + '</td>' +
        '<td>' + types + '</td>' +
        '<td class="text-nowrap">' + esc(a.first_seen) + '</td>' +
        '<td class="text-nowrap">' + esc(a.last_seen) + '</td>' +
        '<td class="text-nowrap"><a href="' + link('/alerts', { source_ip: a.source_ip }) + '">Alerts</a> | ' +
        '<a href="' + link('/logs', { source_ip: a.source_ip }) + '">Logs</a></td></tr>';
    }).join('');
  }

  function renderUsers(items) {
    const body = $('usersBody');
    if (items.length === 0) {
      body.innerHTML = '<tr><td colspan="5" class="text-secondary">No accounts involved yet.</td></tr>';
      return;
    }
    body.innerHTML = items.map(function (u) {
      return '<tr>' +
        '<td>' + esc(u.username) + '</td>' +
        '<td>' + num(u.alerts) + '</td>' +
        '<td>' + num(u.source_ips) + '</td>' +
        '<td>' + esc(Math.round(Number(u.max_score) || 0)) + '</td>' +
        '<td><a href="' + link('/alerts', { username: u.username }) + '">Alerts</a></td></tr>';
    }).join('');
  }

  async function load() {
    const myId = ++loadId;
    const id = scopeId();
    const data = await api('/api/threats' + (id ? '?upload_id=' + encodeURIComponent(id) : ''));
    if (myId !== loadId) return;                    // a newer request is already running
    renderCards(data.totals);
    renderTypeChart(data.by_type);
    renderMethodChart(data.detection_methods);
    renderTypes(data.by_type);
    renderAttackers(data.top_attackers);
    renderUsers(data.targeted_users);
    hideStatus($('statusBox'));
  }

  function reload() {
    load().catch(function (err) { showStatus($('statusBox'), 'danger', err.message); });
  }

  async function init() {
    try {
      const uploads = await api('/api/uploads');
      fillUploads($('scopeSelect'), uploads.items);
      const wanted = new URLSearchParams(window.location.search).get('upload_id');
      if (wanted) {
        const select = $('scopeSelect');
        const ok = Array.prototype.some.call(select.options, function (o) { return o.value === wanted; });
        if (ok) select.value = wanted;
      }
      await load();
    } catch (err) {
      showStatus($('statusBox'), 'danger', err.message);
    }
  }

  $('scopeSelect').addEventListener('change', reload);
  $('refreshBtn').addEventListener('click', reload);
  init();
})();