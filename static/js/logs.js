/* Log viewer page. The shared engine is in listpage.js. */
(function () {
  'use strict';

  const { $, api, fillSelect, logRowHtml } = window.SOC;

  window.createListPage({
    endpoint: '/api/logs',
    bodyId: 'logsBody',
    colspan: 10,
    emptyText: 'No logs match these filters.',
    textFields: ['q', 'source_ip', 'username', 'date_from', 'date_to'],
    selectFields: ['event_type', 'severity'],
    checkField: 'anomalies_only',
    defaultSort: 'timestamp',
    defaultOrder: 'desc',
    rowHtml: function (log) { return logRowHtml(log, true); },
    prepare: async function () {
      const filters = await api('/api/filters');
      fillSelect($('event_type'), filters.event_types, 'All event types');
      fillSelect($('severity'), filters.log_severities, 'All severities');
    }
  }).start();
})();