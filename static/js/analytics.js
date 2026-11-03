/* Analytics page: loads /api/analytics and draws the charts. */
(function () {
  'use strict';

  const { $, num, api, fillUploads, showStatus, hideStatus, SEVERITY_COLORS } = window.SOC;
  const charts = window.SOC.charts;

  const SEVERITIES = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];            // stacking order
  const STATUS_COLORS = { 'New': '#58a6ff', 'Investigating': '#d29922', 'Resolved': '#3fb950',
                          'False Positive': '#8b949e' };
  const METHOD_COLORS = { 'RULE': '#58a6ff', 'ML': '#a371f7', 'RULE+ML': '#3fb950' };
  let loadId = 0;

  function scopeId() { return $('scopeSelect').value; }

  function bucketLabel(bucket, kind) {
    // hour bucket "2026-01-14 03" -> "01-14 03:00"
    return kind === 'hour' ? bucket.slice(5, 10) + ' ' + bucket.slice(11) + ':00' : bucket;
  }

  // One doughnut from {name: count}; zero slices are left out. `colors` maps name -> colour
  function doughnut(canvasId, emptyId, counts, order, colors) {
    const names = order.filter(function (k) { return counts[k] > 0; });
    charts.draw(canvasId, emptyId, names.length === 0, function () {
      return {
        type: 'doughnut',
        data: {
          labels: names,
          datasets: [{
            data: names.map(function (k) { return counts[k]; }),
            backgroundColor: names.map(function (k) { return colors[k] || '#8b949e'; }),
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

  function renderCards(t) {
    $('an-logs').textContent = num(t.logs);
    $('an-alerts').textContent = num(t.alerts);
    $('an-open').textContent = num(t.open_alerts);
    $('an-anomalies').textContent = num(t.anomalies);
  }

  function renderScoreHistogram(items) {
    charts.draw('scoreChart', 'scoreEmpty', items.every(function (b) { return b.count === 0; }), function () {
      return {
        type: 'bar',
        data: {
          labels: items.map(function (b) { return b.label; }),
          datasets: [{ label: 'Alerts', data: items.map(function (b) { return b.count; }),
                       backgroundColor: '#58a6ff', borderWidth: 0 }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: { legend: { display: false } },
          scales: {
            x: { grid: { display: false }, title: { display: true, text: 'Threat score' } },
            y: { beginAtZero: true, ticks: { precision: 0 } }
          }
        }
      };
    }, 'No alerts yet');
  }

  function renderTimeline(timeline) {
    const points = (timeline && timeline.points) || [];
    charts.draw('timelineChart', 'timelineEmpty', points.length === 0, function () {
      return {
        type: 'bar',
        data: {
          labels: points.map(function (p) { return bucketLabel(p.bucket, timeline.bucket); }),
          datasets: SEVERITIES.map(function (s) {
            return { label: s, data: points.map(function (p) { return p[s] || 0; }),
                     backgroundColor: SEVERITY_COLORS[s], borderWidth: 0 };
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
      };
    }, 'No alerts yet');
  }

  function renderHourly(hours) {
    charts.draw('hourlyChart', 'hourlyEmpty', hours.every(function (h) { return h.total === 0; }), function () {
      return {
        type: 'bar',
        data: {
          labels: hours.map(function (h) { return String(h.hour).padStart(2, '0') + ':00'; }),
          datasets: [
            { type: 'bar', label: 'Log events', data: hours.map(function (h) { return h.total; }),
              backgroundColor: 'rgba(88, 166, 255, 0.35)', borderWidth: 0, order: 3 },
            { type: 'line', label: 'In an alert', data: hours.map(function (h) { return h.alerted; }),
              borderColor: '#f0883e', backgroundColor: '#f0883e', tension: 0.25, pointRadius: 2, order: 1 },
            { type: 'line', label: 'ML anomalies', data: hours.map(function (h) { return h.anomalies; }),
              borderColor: '#a371f7', backgroundColor: '#a371f7', tension: 0.25, pointRadius: 2, order: 2 }
          ]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: { legend: { position: 'bottom' } },
          scales: { x: { grid: { display: false } }, y: { beginAtZero: true, ticks: { precision: 0 } } }
        }
      };
    }, 'No logs yet');
  }

  function renderEventTypes(items) {
    charts.draw('eventChart', 'eventEmpty', items.length === 0, function () {
      return {
        type: 'bar',
        data: {
          labels: items.map(function (e) { return e.event_type; }),
          datasets: [
            { label: 'Not in an alert', data: items.map(function (e) { return e.count - e.alerted; }),
              backgroundColor: '#484f58', borderWidth: 0 },
            { label: 'In an alert', data: items.map(function (e) { return e.alerted; }),
              backgroundColor: '#f0883e', borderWidth: 0 }
          ]
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
    }, 'No logs yet');
  }

  function renderMl(items) {
    charts.draw('mlChart', 'mlEmpty', items.length === 0, function () {
      return {
        type: 'bar',
        data: {
          labels: items.map(function (b) { return b.label; }),
          datasets: [
            { label: 'Not flagged', data: items.map(function (b) { return b.count - b.flagged; }),
              backgroundColor: '#58a6ff', borderWidth: 0 },
            { label: 'Flagged as anomaly', data: items.map(function (b) { return b.flagged; }),
              backgroundColor: '#a371f7', borderWidth: 0 }
          ]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: { legend: { position: 'bottom' } },
          scales: {
            x: { stacked: true, grid: { display: false },
                 title: { display: true, text: 'Anomaly score (higher = more unusual)' } },
            y: { stacked: true, beginAtZero: true, ticks: { precision: 0 } }
          }
        }
      };
    }, 'ML did not run (not enough events)');
  }

  function renderCoverage(c) {
    $('ml-scored').textContent = num(c.scored);
    $('ml-anomalies').textContent = num(c.anomalies);
    $('ml-rule-events').textContent = num(c.rule_events);
    $('ml-rule-flagged').textContent = num(c.rule_events_flagged) + ' of ' + num(c.rule_events);
    $('ml-outside').textContent = num(c.anomalies_outside_rules);
  }

  async function load() {
    const myId = ++loadId;
    const id = scopeId();
    const a = await api('/api/analytics' + (id ? '?upload_id=' + encodeURIComponent(id) : ''));
    if (myId !== loadId) return;                    // a newer request is already running
    renderCards(a.totals);
    doughnut('severityChart', 'severityEmpty', a.severity_counts, ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
             SEVERITY_COLORS);
    doughnut('statusChart', 'statusEmpty', a.status_counts,
             ['New', 'Investigating', 'Resolved', 'False Positive'], STATUS_COLORS);
    doughnut('methodChart', 'methodEmpty', a.detection_methods, ['RULE', 'RULE+ML', 'ML'], METHOD_COLORS);
    renderScoreHistogram(a.score_histogram);
    renderTimeline(a.timeline);
    renderHourly(a.hourly);
    renderEventTypes(a.event_types);
    renderMl(a.ml_score_distribution);
    renderCoverage(a.ml_coverage);
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