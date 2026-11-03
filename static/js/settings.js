/* Settings page: shows /api/settings (read-only) and re-analyzes an upload. */
(function () {
  'use strict';

  const { $, esc, api, fillUploads, showStatus } = window.SOC;

  function flatten(obj, prefix, out) {
    Object.keys(obj).forEach(function (key) {
      const value = obj[key], name = prefix ? prefix + '.' + key : key;
      if (value && typeof value === 'object' && !Array.isArray(value)) {
        flatten(value, name, out);
      } else {
        out.push([name, value]);
      }
    });
    return out;
  }

  function fmt(value) {
    if (value === null || value === undefined) return '-';
    return Array.isArray(value) ? value.join(', ') : String(value);
  }

  function table(pairs) {
    return '<table class="table table-sm soc-table kv-table mb-0"><tbody>' + pairs.map(function (p) {
      return '<tr><td>' + esc(p[0]) + '</td><td><code>' + esc(fmt(p[1])) + '</code></td></tr>';
    }).join('') + '</tbody></table>';
  }

  function card(title, bodyHtml) {
    return '<div class="card soc-card h-100"><div class="card-header soc-card-title">' + esc(title) +
      '</div><div class="card-body p-0">' + bodyHtml + '</div></div>';
  }

  function renderValidation(v) {
    const labels = [['detection_rules', 'Detection rules'], ['ml', 'Machine learning'],
                    ['scoring', 'Threat scoring'], ['severity_bands', 'Severity bands']];
    $('validationBox').innerHTML = labels.map(function (pair) {
      const item = v[pair[0]];
      const badge = item.valid
        ? '<span class="st-badge st-resolved">valid</span>'
        : '<span class="sev-badge sev-critical">invalid</span>';
      return '<div class="mb-1">' + badge + ' <strong>' + esc(pair[1]) + '</strong>' +
        (item.valid ? '' : '<div class="text-danger small ms-2">' + esc(item.error) + '</div>') + '</div>';
    }).join('') + (v.all_valid ? '' :
      '<div class="mt-2 small text-secondary">Fix the value in config.py and restart the app. ' +
      'Analyses will fail until all settings are valid.</div>');
  }

  function render(s) {
    renderValidation(s.validation);

    $('rulesBox').innerHTML = Object.keys(s.detection_rules).map(function (name) {
      return '<div class="col-md-6 col-xl-4">' + card(name, table(flatten(s.detection_rules[name], '', []))) + '</div>';
    }).join('');

    $('mlBox').innerHTML = card('Machine learning (Isolation Forest)', table(flatten(s.ml, '', [])));
    $('bandsBox').innerHTML = card('Severity bands (score 0-100)', table(
      Object.keys(s.severity_bands).map(function (k) {
        return [k, s.severity_bands[k][0] + ' to ' + s.severity_bands[k][1]];
      })));
    $('limitsBox').innerHTML = card('Limits', table(flatten(s.limits, '', [])));
    $('scoringBox').innerHTML = card('Scoring weights', table(flatten(s.scoring, '', [])));
  }

  async function reanalyze() {
    const id = $('reanalyzeSelect').value;
    const box = $('statusBox'), button = $('reanalyzeBtn');
    if (!id) return showStatus(box, 'warning', 'Choose an upload first.');
    button.disabled = true;
    showStatus(box, 'info', 'Re-analyzing...');
    try {
      const a = await api('/api/uploads/' + encodeURIComponent(id) + '/analyze', { method: 'POST' });
      showStatus(box, 'success', 'Upload #' + id + ' re-analyzed: ' + a.total_alerts + ' alerts, ' +
        a.anomaly_count + ' ML anomalies. Alert statuses were reset to New.');
    } catch (err) {
      showStatus(box, 'danger', err.message);
    } finally {
      button.disabled = false;
    }
  }

  async function init() {
    try {
      const results = await Promise.all([api('/api/settings'), api('/api/uploads')]);
      render(results[0]);
      fillUploads($('reanalyzeSelect'), results[1].items);
      $('reanalyzeSelect').options[0].textContent = 'Choose an upload...';
    } catch (err) {
      showStatus($('statusBox'), 'danger', err.message);
    }
  }

  $('reanalyzeBtn').addEventListener('click', reanalyze);
  init();
})();