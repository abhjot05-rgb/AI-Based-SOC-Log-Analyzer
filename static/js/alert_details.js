/* Alert investigation page: loads /api/alerts/<id> and fills the page. */
(function () {
  'use strict';

  const { $, esc, api, sevBadge, queryString, showStatus, hideStatus, logRowHtml } = window.SOC;

  const alertId = $('alertRoot').dataset.alertId;
  const METHOD_TEXT = {
    'RULE': 'Found by a configurable detection rule.',
    'ML': 'Flagged only by the Isolation Forest model: an unusual-behaviour lead, not a confirmed attack.',
    'RULE+ML': 'Found by a rule, and the ML model also flagged events inside it as unusual.'
  };

  function setText(id, value) {
    $(id).textContent = (value === null || value === undefined || value === '') ? '-' : String(value);
  }

  // The stored original log is JSON for CSV/JSON uploads: pretty-print it when possible
  function pretty(raw) {
    if (!raw) return '-';
    try { return JSON.stringify(JSON.parse(raw), null, 2); } catch (err) { return String(raw); }
  }

  function renderSeverityReason(text) {
    const box = $('dSeverityReason');
    if (!text) { box.textContent = '-'; return; }
    // The explanation is a few sentences; show each one as its own paragraph
    box.innerHTML = String(text).split(/\.\s+(?=[A-Z])/).map(function (sentence) {
      return '<p class="mb-2">' + esc(sentence.trim().replace(/\.*$/, '.')) + '</p>';
    }).join('');
  }

  function render(a) {
    setText('dAlertId', '#' + a.id);
    $('dSeverity').innerHTML = sevBadge(a.severity);
    setText('dThreatType', a.threat_type);
    setText('dTimestamp', a.timestamp);
    setText('dSourceIp', a.source_ip);
    setText('dDestIp', a.destination_ip);
    setText('dUsername', a.username);
    setText('dEventId', a.event_id);
    setText('dMethod', a.detection_method);
    setText('dMethodNote', METHOD_TEXT[a.detection_method] || '');

    const ml = a.ml_anomaly_score;
    setText('dMlScore', ml === null || ml === undefined ? 'Not available (ML did not run for this file)'
                                                          : Number(ml).toFixed(3));
    const score = Number(a.threat_score) || 0;
    setText('dThreatScore', Math.round(score) + ' / 100');
    $('dScoreBar').style.width = Math.max(0, Math.min(100, score)) + '%';
    setText('dRelatedCount', a.related_event_count);

    setText('dReason', a.reason);
    renderSeverityReason(a.severity_reason);

    const steps = a.recommended_steps || [];
    $('dSteps').innerHTML = steps.length
      ? steps.map(function (s) { return '<li>' + esc(s) + '</li>'; }).join('')
      : '<li class="text-secondary">No recommendations stored.</li>';

    $('dOriginalLog').textContent = pretty(a.original_log);

    const related = a.related_logs || [];
    $('dRelatedBody').innerHTML = related.length
      ? related.map(function (l) { return logRowHtml(l, false); }).join('')
      : '<tr><td colspan="9" class="text-secondary">No related events stored.</td></tr>';
    $('dRelatedNote').textContent = 'Showing ' + related.length + ' of ' + a.related_total;

    const link = $('logsLink');
    if (a.source_ip) {
      link.href = '/logs?' + queryString({ source_ip: a.source_ip, upload_id: a.upload_id });
      link.classList.remove('d-none');
    }
    $('statusSelect').value = a.status;
  }

  async function load() {
    const a = await api('/api/alerts/' + encodeURIComponent(alertId));
    render(a);
  }

  async function saveStatus() {
    const button = $('saveStatusBtn');
    button.disabled = true;
    try {
      const result = await api('/api/alerts/' + encodeURIComponent(alertId) + '/status', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: $('statusSelect').value })
      });
      await load();
      showStatus($('statusBox'), 'success', 'Status saved: ' + result.status + '.');
    } catch (err) {
      showStatus($('statusBox'), 'danger', err.message);
    } finally {
      button.disabled = false;
    }
  }

  async function init() {
    try {
      const filters = await api('/api/filters');
      const select = $('statusSelect');
      select.textContent = '';
      filters.statuses.forEach(function (s) {
        const opt = document.createElement('option');
        opt.value = s;
        opt.textContent = s;
        select.appendChild(opt);
      });
      hideStatus($('statusBox'));
      await load();
    } catch (err) {
      $('alertContent').classList.add('d-none');
      showStatus($('statusBox'), 'danger', err.message);
    }
  }

  $('saveStatusBtn').addEventListener('click', saveStatus);
  init();
})();