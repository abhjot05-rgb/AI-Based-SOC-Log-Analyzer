/* Shared engine for the Logs and Alerts pages:
   filters, sorting, pagination, URL sync and safe loading. */
(function () {
  'use strict';

  const { $, api, debounce, queryString, fillUploads, renderPager, showStatus, hideStatus } = window.SOC;

  /*
    cfg = {
      endpoint, bodyId, colspan, emptyText,
      textFields: [ids of text/date inputs], selectFields: [ids of selects], checkField: id or null,
      defaultSort, defaultOrder, rowHtml(item), prepare(): async function that fills the selects
    }
  */
  window.createListPage = function (cfg) {
    const state = { page: 1, sort: cfg.defaultSort, order: cfg.defaultOrder };
    const sortHeaders = Array.prototype.slice.call(document.querySelectorAll('th[data-sort]'));
    const sortKeys = sortHeaders.map(function (th) { return th.dataset.sort; });
    const filterIds = cfg.textFields.concat(cfg.selectFields);
    let loadId = 0;          // lets us ignore responses that arrive out of order
    let errorShown = false;

    function notice(kind, message) {
      errorShown = kind === 'danger';
      showStatus($('statusBox'), kind, message);
    }

    // A select must only be set to a value it actually offers (otherwise it shows blank)
    function setValue(el, value) {
      if (el.tagName === 'SELECT') {
        const ok = Array.prototype.some.call(el.options, function (o) { return o.value === value; });
        if (ok) el.value = value;
      } else {
        el.value = value;
      }
    }

    function readUrl() {
      const p = new URLSearchParams(window.location.search);
      filterIds.forEach(function (id) { if (p.has(id)) setValue($(id), p.get(id)); });
      if (p.has('upload_id')) setValue($('scopeSelect'), p.get('upload_id'));
      if (p.has('per_page')) setValue($('per_page'), p.get('per_page'));
      if (cfg.checkField) {
        $(cfg.checkField).checked =
          ['1', 'true', 'yes', 'on'].indexOf((p.get(cfg.checkField) || '').toLowerCase()) >= 0;
      }
      const page = parseInt(p.get('page'), 10);
      if (page >= 1) state.page = page;
      if (sortKeys.indexOf(p.get('sort')) >= 0) state.sort = p.get('sort');
      if (['asc', 'desc'].indexOf(p.get('order')) >= 0) state.order = p.get('order');
    }

    function currentParams() {
      const params = {
        page: state.page, sort: state.sort, order: state.order,
        per_page: $('per_page').value, upload_id: $('scopeSelect').value
      };
      filterIds.forEach(function (id) { params[id] = $(id).value.trim(); });
      if (cfg.checkField) params[cfg.checkField] = $(cfg.checkField).checked ? '1' : '';
      return params;
    }

    function updateSortIndicators() {
      sortHeaders.forEach(function (th) {
        const mark = th.querySelector('.sort-ind');
        mark.textContent = th.dataset.sort === state.sort ? (state.order === 'asc' ? ' ▲' : ' ▼') : '';
      });
    }

    async function load() {
      const myId = ++loadId;
      const qs = queryString(currentParams());
      try {
        const data = await api(cfg.endpoint + '?' + qs);
        if (myId !== loadId) return;                       // a newer request is already running
        if (data.items.length === 0 && data.total > 0 && state.page > data.pages) {
          state.page = data.pages;                         // the page no longer exists: go to the last one
          return load();
        }
        if (errorShown) { hideStatus($('statusBox')); errorShown = false; }
        $(cfg.bodyId).innerHTML = data.items.length
          ? data.items.map(cfg.rowHtml).join('')
          : '<tr><td colspan="' + cfg.colspan + '" class="text-secondary">' + cfg.emptyText + '</td></tr>';
        renderPager($('pager'), data, function (p) { state.page = p; load(); });
        updateSortIndicators();
        window.history.replaceState(null, '', '?' + qs);   // keeps the filters in the address bar
      } catch (err) {
        if (myId === loadId) notice('danger', err.message);
      }
    }

    function bindEvents() {
      const changed = function () { state.page = 1; load(); };
      const typed = debounce(changed, 350);
      cfg.textFields.forEach(function (id) { $(id).addEventListener('input', typed); });
      cfg.selectFields.concat(['scopeSelect', 'per_page'], cfg.checkField ? [cfg.checkField] : [])
        .forEach(function (id) { $(id).addEventListener('change', changed); });
      $('filterForm').addEventListener('submit', function (e) { e.preventDefault(); changed(); });
      $('resetBtn').addEventListener('click', function () {
        $('filterForm').reset();
        state.sort = cfg.defaultSort;
        state.order = cfg.defaultOrder;
        changed();
      });
      sortHeaders.forEach(function (th) {
        th.addEventListener('click', function () {
          if (state.sort === th.dataset.sort) {
            state.order = state.order === 'asc' ? 'desc' : 'asc';
          } else {
            state.sort = th.dataset.sort;
            state.order = 'asc';
          }
          state.page = 1;
          load();
        });
      });
    }

    async function start() {
      try {
        const uploads = await api('/api/uploads');
        fillUploads($('scopeSelect'), uploads.items);
        if (cfg.prepare) await cfg.prepare();
        readUrl();
        updateSortIndicators();
        bindEvents();
        await load();
      } catch (err) {
        notice('danger', err.message);
      }
    }

    return { start: start, reload: load, notice: notice };
  };
})();