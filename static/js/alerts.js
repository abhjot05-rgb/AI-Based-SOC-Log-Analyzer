/* Alerts page: table, filters and inline status change. */
(function () {
  'use strict';

  const { $, esc, api, sevBadge, fillSelect } = window.SOC;

  let statuses = ['New', 'Investigating', 'Resolved', 'False Positive'];

  function statusSelect(a) {
    const options = statuses.map(function (s) {
      return '<option value="' + esc(s) + '"' + (s === a.status ? ' selected' : '') + '>' + esc(s) + '</option>';
    }).join('');
    return '<select class="form-select form-select-sm status-select" data-id="' + esc(a.id) +
      '" aria-label="Status of alert ' + esc(a.id) + '">' + options + '</select>';
  }

  function rowHtml(a) {
    return '<tr>' +
      '<td><a href="/alerts/' + encodeURIComponent(a.id) + '">#' + esc(a.id) + '</a></td>' +
      '<td class="text-nowrap">' + esc(a.timestamp) + '</td>' +
      '<td>' + esc(a.threat_type) + '</td>' +
      '<td>' + sevBadge(a.severity) + '</td>' +
      '<td>' + esc(Math.round(Number(a.threat_score) || 0)) + '</td>' +
      '<td>' + esc(a.detection_method) + '</td>' +
      '<td><code>' + esc(a.source_ip || '-') + '</code></td>' +
      '<td>' + esc(a.username || '-') + '</td>' +
      '<td>' + esc(a.related_event_count) + '</td>' +
      '<td>' + statusSelect(a) + '</td></tr>';
  }

  const page = window.createListPage({
    endpoint: '/api/alerts',
    bodyId: 'alertsBody',
    colspan: 10,
    emptyText: 'No alerts match these filters.',
    textFields: ['q', 'source_ip', 'username', 'date_from', 'date_to'],
    selectFields: ['severity', 'status', 'threat_type', 'detection_method'],
    checkField: null,
    defaultSort: 'timestamp',
    defaultOrder: 'desc',
    rowHtml: rowHtml,
    prepare: async function () {
      const f = await api('/api/filters');
      statuses = f.statuses;
      fillSelect($('severity'), f.severities, 'All severities');
      fillSelect($('status'), f.statuses, 'All statuses');
      fillSelect($('threat_type'), f.threat_types, 'All threat types');
      fillSelect($('detection_method'), f.detection_methods, 'All methods');
    }
  });

  // One listener for every row's status dropdown
  $('alertsBody').addEventListener('change', async function (event) {
    const select = event.target.closest('select.status-select');
    if (!select) return;
    select.disabled = true;
    try {
      const result = await api('/api/alerts/' + encodeURIComponent(select.dataset.id) + '/status', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: select.value })
      });
      page.notice('success', 'Alert #' + result.id + ' set to ' + result.status + '.');
    } catch (err) {
      page.notice('danger', err.message);
    }
    await page.reload();     // shows the saved value (or restores the old one after an error)
  });

  page.start();
})();