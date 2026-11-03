/* Shared helpers for every page. Loaded on all pages (see base.html). */
(function () {
  'use strict';

  const SEVERITY_COLORS = { LOW: '#58a6ff', MEDIUM: '#d29922', HIGH: '#f0883e', CRITICAL: '#f85149' };

  function $(id) { return document.getElementById(id); }

  // Log data is untrusted: always escape it before putting it in HTML.
  function esc(value) {
    return String(value === null || value === undefined ? '' : value)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  function num(value) {
    const n = Number(value);
    return Number.isFinite(n) ? n.toLocaleString() : '0';
  }

  async function api(url, options) {
    let response;
    try {
      response = await fetch(url, options);
    } catch (err) {
      throw new Error('Cannot reach the server. Is "python app.py" still running?');
    }
    let data = null;
    try { data = await response.json(); } catch (err) { /* response was not JSON */ }
    if (!response.ok) {
      throw new Error((data && data.error) || ('Request failed (' + response.status + ')'));
    }
    return data;
  }

  function sevBadge(severity) {
    const s = String(severity || 'NONE').toUpperCase();
    return '<span class="sev-badge sev-' + esc(s.toLowerCase()) + '">' + esc(s) + '</span>';
  }

  function statusBadge(status) {
    const text = String(status || '');
    const cls = 'st-' + text.toLowerCase().replace(/[^a-z]+/g, '-');
    return '<span class="st-badge ' + esc(cls) + '">' + esc(text) + '</span>';
  }

  // box.textContent is used (not innerHTML), so messages can never inject HTML.
  function showStatus(box, kind, message) {
    box.className = 'mt-3 alert alert-' + kind;
    box.textContent = message;
  }

  function hideStatus(box) {
    box.className = 'mt-3 d-none';
    box.textContent = '';
  }

  // ---------------------------------------------------------------- list-page helpers
  function debounce(fn, ms) {
    let timer = null;
    return function () {
      const args = arguments, self = this;
      clearTimeout(timer);
      timer = setTimeout(function () { fn.apply(self, args); }, ms);
    };
  }

  // {a: 1, b: ''} -> "a=1"  (empty values are left out)
  function queryString(obj) {
    const p = new URLSearchParams();
    Object.keys(obj).forEach(function (key) {
      const v = obj[key];
      if (v !== undefined && v !== null && String(v) !== '') p.set(key, v);
    });
    return p.toString();
  }

  function keepSelection(select, previous) {
    const exists = Array.prototype.some.call(select.options, function (o) { return o.value === previous; });
    select.value = exists ? previous : '';
  }

  function fillSelect(select, values, allLabel) {
    const previous = select.value;
    select.textContent = '';
    const first = document.createElement('option');
    first.value = '';
    first.textContent = allLabel;
    select.appendChild(first);
    values.forEach(function (v) {
      const opt = document.createElement('option');
      opt.value = String(v);
      opt.textContent = String(v);
      select.appendChild(opt);
    });
    keepSelection(select, previous);
  }

  function fillUploads(select, items) {
    const previous = select.value;
    select.textContent = '';
    const first = document.createElement('option');
    first.value = '';
    first.textContent = 'All uploads';
    select.appendChild(first);
    items.forEach(function (u) {
      const opt = document.createElement('option');
      opt.value = String(u.id);
      opt.textContent = '#' + u.id + '  ' + u.original_name;
      select.appendChild(opt);
    });
    keepSelection(select, previous);
  }

  // data = {total, page, pages, per_page} from the API; onPage(n) is called when a button is clicked
  function renderPager(box, data, onPage) {
    box.textContent = '';
    const info = document.createElement('span');
    info.className = 'text-secondary small';
    if (!data.total) {
      info.textContent = 'No results';
      box.appendChild(info);
      return;
    }
    const from = (data.page - 1) * data.per_page + 1;
    const to = Math.min(data.total, data.page * data.per_page);
    info.textContent = num(from) + '-' + num(to) + ' of ' + num(data.total) +
      ' results (page ' + data.page + ' of ' + data.pages + ')';
    box.appendChild(info);

    const group = document.createElement('div');
    group.className = 'btn-group btn-group-sm';
    [['«', 1, 'First page'], ['‹ Prev', data.page - 1, 'Previous page'],
     ['Next ›', data.page + 1, 'Next page'], ['»', data.pages, 'Last page']].forEach(function (b) {
      const button = document.createElement('button');
      button.type = 'button';
      button.className = 'btn btn-outline-secondary';
      button.textContent = b[0];
      button.setAttribute('aria-label', b[2]);
      const target = b[1];
      button.disabled = target < 1 || target > data.pages || target === data.page;
      button.addEventListener('click', function () { onPage(target); });
      group.appendChild(button);
    });
    box.appendChild(group);
  }

  // ---------------------------------------------------------------- log rows
  function mlBadge(isAnomaly, score) {
    const n = (score === null || score === undefined || score === '') ? NaN : Number(score);
    const text = Number.isFinite(n) ? n.toFixed(2) : '';
    if (isAnomaly) {
      return '<span class="ml-badge" title="Flagged as unusual by the Isolation Forest model">ANOMALY ' +
        esc(text) + '</span>';
    }
    return text ? '<small class="text-secondary">' + esc(text) + '</small>'
                : '<span class="text-secondary">-</span>';
  }

  // One table row for a log event. Column order matches logs.html and alert_details.html.
  function logRowHtml(l, withMessage) {
    return '<tr>' +
      '<td class="text-nowrap">' + esc(l.timestamp) + '</td>' +
      '<td><code>' + esc(l.source_ip || '-') + '</code></td>' +
      '<td><code>' + esc(l.destination_ip || '-') + '</code></td>' +
      '<td>' + esc(l.username || '-') + '</td>' +
      '<td>' + esc(l.event_id === null || l.event_id === undefined ? '-' : l.event_id) + '</td>' +
      '<td>' + esc(l.event_type || '-') + '</td>' +
      '<td>' + esc(l.status || '-') + '</td>' +
      '<td>' + sevBadge(l.severity) + '</td>' +
      '<td>' + mlBadge(l.is_anomaly, l.anomaly_score) + '</td>' +
      (withMessage
        ? '<td class="msg-cell" title="' + esc(l.message || '') + '">' + esc(l.message || '-') + '</td>'
        : '') +
      '</tr>';
  }

  // Sidebar toggle on small screens
  const sidebar = $('sidebar'), backdrop = $('backdrop'), menuBtn = $('menuBtn');
  function setMenu(open) {
    if (!sidebar) return;
    sidebar.classList.toggle('open', open);
    backdrop.classList.toggle('show', open);
  }
  if (menuBtn) menuBtn.addEventListener('click', function () { setMenu(!sidebar.classList.contains('open')); });
  if (backdrop) backdrop.addEventListener('click', function () { setMenu(false); });

  window.SOC = {
    $, esc, num, api, sevBadge, statusBadge, showStatus, hideStatus, SEVERITY_COLORS,
    debounce, queryString, fillSelect, fillUploads, renderPager, mlBadge, logRowHtml
  };
})();