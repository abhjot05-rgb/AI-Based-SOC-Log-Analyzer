/* Reports page: builds the download links from the chosen scope and filters. */
(function () {
  'use strict';

  const { $, esc, num, api, fillSelect, fillUploads, queryString, showStatus } = window.SOC;

  function scope() { return $('scopeSelect').value; }

  function updateLinks() {
    const up = scope();
    $('alertsCsvLink').setAttribute('href', '/api/export/alerts.csv?' + queryString({
      upload_id: up, severity: $('alertSeverity').value, status: $('alertStatus').value }));
    $('logsCsvLink').setAttribute('href', '/api/export/logs.csv?' + queryString({
      upload_id: up, severity: $('logSeverity').value,
      anomalies_only: $('logAnomalies').checked ? '1' : '' }));
    const s = queryString({ upload_id: up });
    $('summaryViewLink').setAttribute('href', '/reports/summary' + (s ? '?' + s : ''));
    $('summaryDownloadLink').setAttribute('href',
      '/reports/summary?' + queryString({ upload_id: up, download: '1' }));
    $('summaryJsonLink').setAttribute('href', '/api/reports/summary' + (s ? '?' + s : ''));
  }

  function renderUploads(items) {
    const body = $('uploadsBody');
    if (items.length === 0) {
      body.innerHTML = '<tr><td colspan="7" class="text-secondary">No uploads yet. ' +
        'Generate demo data or upload a file on the Dashboard.</td></tr>';
      return;
    }
    body.innerHTML = items.map(function (u) {
      const id = encodeURIComponent(u.id);
      return '<tr>' +
        '<td>#' + esc(u.id) + '</td>' +
        '<td>' + esc(u.original_name) + '</td>' +
        '<td>' + esc(u.file_type) + '</td>' +
        '<td>' + num(u.total_rows) + '</td>' +
        '<td>' + (u.total_alerts === null || u.total_alerts === undefined ? '-' : num(u.total_alerts)) + '</td>' +
        '<td>' + esc(u.status) + '</td>' +
        '<td class="text-nowrap">' +
          '<a href="/api/export/alerts.csv?upload_id=' + id + '">Alerts CSV</a> | ' +
          '<a href="/api/export/logs.csv?upload_id=' + id + '">Logs CSV</a> | ' +
          '<a href="/reports/summary?upload_id=' + id + '" target="_blank" rel="noopener">Summary</a>' +
        '</td></tr>';
    }).join('');
  }

  async function init() {
    try {
      const results = await Promise.all([api('/api/uploads'), api('/api/filters')]);
      const uploads = results[0], f = results[1];
      fillUploads($('scopeSelect'), uploads.items);
      fillSelect($('alertSeverity'), f.severities, 'All severities');
      fillSelect($('alertStatus'), f.statuses, 'All statuses');
      fillSelect($('logSeverity'), f.log_severities, 'All severities');
      renderUploads(uploads.items);
      updateLinks();
    } catch (err) {
      showStatus($('statusBox'), 'danger', err.message);
    }
  }

  ['scopeSelect', 'alertSeverity', 'alertStatus', 'logSeverity', 'logAnomalies'].forEach(function (id) {
    $(id).addEventListener('change', updateLinks);
  });
  init();
})();