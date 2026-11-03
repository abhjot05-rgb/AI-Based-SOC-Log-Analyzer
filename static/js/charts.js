/* Chart helper for the Threats and Analytics pages. Loaded after Chart.js and soc.js. */
(function () {
  'use strict';

  const { $ } = window.SOC;
  const ready = typeof window.Chart !== 'undefined';
  const PALETTE = ['#58a6ff', '#f85149', '#d29922', '#3fb950', '#a371f7', '#f0883e', '#39c5cf', '#db61a2'];

  if (ready) {
    Chart.defaults.color = '#9da7b3';
    Chart.defaults.borderColor = '#30363d';
    Chart.defaults.font.family = '"Segoe UI", system-ui, Arial, sans-serif';
  }

  const registry = {};      // canvas id -> Chart, so a redraw replaces the old chart

  /*
    Draw (or clear) one chart.
    isEmpty: true when there is nothing to show; makeConfig(): returns the Chart.js config.
  */
  function draw(canvasId, emptyId, isEmpty, makeConfig, emptyText) {
    if (registry[canvasId]) {
      registry[canvasId].destroy();
      delete registry[canvasId];
    }
    const hidden = isEmpty || !ready;
    $(canvasId).classList.toggle('d-none', hidden);
    const box = $(emptyId);
    box.classList.toggle('d-none', !hidden);
    box.textContent = ready
      ? (emptyText || 'No data yet')
      : 'Chart library not loaded. Check your internet connection or use the offline copies (Stage 9 notes).';
    if (!hidden) registry[canvasId] = new Chart($(canvasId), makeConfig());
  }

  window.SOC.charts = { draw: draw, ready: ready, PALETTE: PALETTE };
})();