/* EfCore.TamperEvident dashboard. No dependencies; every node is built with createElement and textContent. */
(() => {
  'use strict';

  // ------------------------------------------------------------------ helpers
  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));
  const SVG_NS = 'http://www.w3.org/2000/svg';

  /** Tiny hyperscript: h('div', {class: 'x', onclick: fn, text: 'hi'}, child, child...). */
  function h(tag, props, ...children) {
    const el = document.createElement(tag);
    applyProps(el, props);
    appendChildren(el, children);
    return el;
  }

  function s(tag, props, ...children) {
    const el = document.createElementNS(SVG_NS, tag);
    applyProps(el, props);
    appendChildren(el, children);
    return el;
  }

  function applyProps(el, props) {
    if (!props) return;
    for (const [key, value] of Object.entries(props)) {
      if (value === undefined || value === null || value === false) continue;
      if (key === 'class') el.setAttribute('class', value);
      else if (key === 'text') el.textContent = value;
      else if (key === 'style') {
        for (const [name, v] of Object.entries(value)) {
          if (name.startsWith('--')) el.style.setProperty(name, String(v));
          else el.style[name] = v;
        }
      }
      else if (key.startsWith('on') && typeof value === 'function') el.addEventListener(key.slice(2), value);
      else if (key === 'value') el.value = value;
      else if (key === 'checked' || key === 'disabled' || key === 'hidden') el[key] = Boolean(value);
      else el.setAttribute(key, value === true ? '' : String(value));
    }
  }

  function appendChildren(el, children) {
    for (const child of children.flat(Infinity)) {
      if (child === null || child === undefined || child === false) continue;
      el.append(child instanceof Node ? child : document.createTextNode(String(child)));
    }
  }

  const icon = (name, extra) => {
    const svg = s('svg', { class: 'ic' + (extra ? ' ' + extra : ''), 'aria-hidden': 'true' }, s('use', { href: '#i-' + name }));
    return svg;
  };

  const number = new Intl.NumberFormat();
  const dateTime = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'medium' });
  const dateShort = new Intl.DateTimeFormat(undefined, { month: 'short', day: 'numeric' });
  const weekday = new Intl.DateTimeFormat(undefined, { weekday: 'short' });
  const relative = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' });

  function when(value) {
    return value ? new Date(value) : null;
  }

  function relTime(value) {
    const date = when(value);
    if (!date) return 'never';
    const seconds = Math.round((date.getTime() - Date.now()) / 1000);
    const units = [['year', 31536000], ['month', 2592000], ['day', 86400], ['hour', 3600], ['minute', 60]];
    for (const [unit, size] of units) {
      if (Math.abs(seconds) >= size) return relative.format(Math.round(seconds / size), unit);
    }
    return Math.abs(seconds) < 10 ? 'just now' : relative.format(seconds, 'second');
  }

  const shortHash = (hash) => (hash ? `${hash.slice(0, 8)}…${hash.slice(-4)}` : '—');
  const plural = (n, one, many) => `${number.format(n)} ${n === 1 ? one : many}`;

  const PALETTE = [['#6aa0ff', '#5a4bff'], ['#ff8fb1', '#ff4d8d'], ['#6ee7c8', '#12b5a3'], ['#ffc56b', '#ff8a1f'], ['#c79bff', '#8e4dff'], ['#8bd3ff', '#2d8cff']];
  function avatar(user) {
    let hash = 0;
    for (const ch of user || '?') hash = (hash * 31 + ch.charCodeAt(0)) >>> 0;
    const [c1, c2] = PALETTE[hash % PALETTE.length];
    return h('span', { class: 'avatar', style: { '--h1': c1, '--h2': c2 }, 'aria-hidden': 'true' }, (user || '?').trim().charAt(0) || '?');
  }

  const userChip = (user) => h('span', { class: 'user' }, avatar(user), h('span', { text: user }));
  const actionClass = (action) => String(action).toLowerCase();
  const actionPill = (action) => h('span', { class: 'pill ' + actionClass(action), text: action });

  function toast(message, kind = 'ok') {
    const el = h('div', { class: 'toast glass ' + kind, role: 'status' }, icon(kind === 'ok' ? 'check' : 'warn'), h('span', { text: message }));
    $('#toasts').append(el);
    setTimeout(() => {
      el.classList.add('leaving');
      setTimeout(() => el.remove(), 380);
    }, kind === 'ok' ? 3200 : 6000);
  }

  async function copy(text, label = 'Copied') {
    try {
      await navigator.clipboard.writeText(text);
      toast(label);
    } catch {
      toast('Copy is not available here', 'bad');
    }
  }

  const store = {
    get(key) { try { return localStorage.getItem(key); } catch { return null; } },
    set(key, value) { try { localStorage.setItem(key, value); } catch { /* storage is optional */ } }
  };

  // ---------------------------------------------------------------------- API
  async function api(path, options = {}) {
    const headers = { Accept: 'application/json', 'X-Requested-With': 'tamper-evident' };
    if (options.body !== undefined) headers['Content-Type'] = 'application/json';
    const response = await fetch('api/' + path, {
      method: options.method || 'GET',
      headers,
      body: options.body !== undefined ? JSON.stringify(options.body) : undefined,
      credentials: 'same-origin'
    });
    if (!response.ok) {
      let detail = `${response.status} ${response.statusText}`;
      try {
        const problem = await response.json();
        detail = problem.detail || problem.title || detail;
      } catch { /* not JSON */ }
      const error = new Error(detail);
      error.status = response.status;
      throw error;
    }
    return response.json();
  }

  // -------------------------------------------------------------------- state
  const state = {
    overview: null,
    verifying: false,
    chainTable: null,
    trail: { table: '', action: [], user: '', recordId: '', from: '', to: '', q: '', page: 1, pageSize: 25 }
  };

  const view = $('#view');
  const ACTIONS = [
    ['Added', 'added', 'var(--green)'],
    ['Modified', 'modified', 'var(--blue)'],
    ['Deleted', 'deleted', 'var(--red)'],
    ['SoftDelete', 'softDelete', 'var(--orange)'],
    ['Restored', 'restored', 'var(--teal)']
  ];

  async function loadOverview() {
    state.overview = await api('overview');
    $('#brand-title').textContent = state.overview.title || 'Tamper Evident';
    document.title = state.overview.title || 'Tamper Evident';
    $('#nav-export').hidden = !state.overview.capabilities.export;
    renderSidebarTables();
    return state.overview;
  }

  function tableStatus(name) {
    const verification = state.overview && state.overview.verification;
    if (!verification) return 'idle';
    const result = verification.tables.find((t) => t.table === name);
    if (!result) return verification.isValid ? 'ok' : 'idle';
    return result.isValid ? 'ok' : 'bad';
  }

  function renderSidebarTables() {
    const list = $('#side-tables');
    list.replaceChildren();
    for (const table of state.overview.tables) {
      list.append(h('a', { class: 'table-item', role: 'listitem', href: '#/trail?table=' + encodeURIComponent(table.table), title: table.table },
        h('i', { class: 'dot ' + tableStatus(table.table) }),
        h('span', { class: 'name', text: table.table }),
        h('span', { class: 'count', text: number.format(table.records) })));
    }
    if (!state.overview.tables.length) list.append(h('p', { class: 'faint', style: { padding: '4px 12px' }, text: 'No audited tables yet.' }));
  }

  /** A plain-language reading of a failed verification result. */
  function explain(result) {
    const where = result.table ? `table ${result.table}` : 'the audit trail';
    const entry = result.failedSequence ? `entry #${result.failedSequence} of ${result.table}` : null;
    switch (result.failure) {
      case 'DataManipulated': return `${entry ? entry[0].toUpperCase() + entry.slice(1) : 'An entry of ' + where} no longer matches its seal: its content, user or time was changed outside of the application.`;
      case 'ChainBroken': return `The hash chain of ${where} is broken${result.failedSequence ? ` at entry #${result.failedSequence}` : ''}: an entry was removed, inserted or reordered.`;
      case 'SequenceGap': return `The sequence of ${where} has a gap${result.failedSequence ? ` at entry #${result.failedSequence}` : ''}: entries were removed or reordered.`;
      case 'RecordsMissing': return `The newest entries of ${where} were deleted: the signed chain head expects more than what is stored.`;
      case 'RecordsBeyondHead': return `Entries exist behind the chain head of ${where}: they were added without going through the audit trail.`;
      case 'ChainStateTampered': return `The signed chain head of ${where} was modified or its signature was removed.`;
      case 'ChainStateMissing': return `The chain head of ${where} was deleted while its entries still exist.`;
      case 'UnknownKey': return `${entry ? entry[0].toUpperCase() + entry.slice(1) : 'An entry'} was sealed with a key that is not configured.`;
      case 'AnchorMismatch': return 'An anchor that was stored outside the database does not occur in the chain: the history was rewritten.';
      default: return result.message;
    }
  }

  // ------------------------------------------------------------------- router
  function parseRoute() {
    const raw = location.hash.replace(/^#\/?/, '');
    const [path, query = ''] = raw.split('?');
    return { name: path || 'overview', params: new URLSearchParams(query) };
  }

  function navigate(hash) {
    if (location.hash === hash) render();
    else location.hash = hash;
  }

  const TITLES = { overview: 'Overview', trail: 'Audit trail', verify: 'Verify integrity', export: 'Export' };

  async function render() {
    closeDrawer();
    const route = parseRoute();
    const name = TITLES[route.name] ? route.name : 'overview';
    $('#page-title').textContent = TITLES[name];
    $$('.nav-item').forEach((a) => a.classList.toggle('active', a.dataset.route === name));
    if (name !== 'overview' && state.overview === null) {
      try { await loadOverview(); } catch (error) { return showError(error); }
    }
    window.scrollTo({ top: 0 });
    view.style.animation = 'none';
    void view.offsetWidth;
    view.style.animation = '';
    try {
      if (name === 'overview') await renderOverview();
      else if (name === 'trail') await renderTrail(route.params);
      else if (name === 'verify') renderVerify();
      else if (name === 'export') renderExport();
    } catch (error) {
      showError(error);
    }
  }

  function showError(error) {
    const forbidden = error.status === 401 || error.status === 403;
    view.replaceChildren(h('div', { class: 'card glass' }, h('div', { class: 'empty' },
      icon(forbidden ? 'key' : 'warn'),
      h('strong', { text: forbidden ? 'Access denied' : 'Something went wrong' }),
      h('p', { text: error.message }),
      h('button', { class: 'btn', type: 'button', onclick: () => { state.overview = null; render(); } }, icon('refresh'), h('span', { text: 'Try again' })))));
  }

  const skeletonBlock = (height) => h('div', { class: 'skeleton', style: { height: height + 'px' } });

  // ----------------------------------------------------------------- overview
  async function renderOverview() {
    view.replaceChildren(
      h('div', { class: 'glass card' }, skeletonBlock(104)),
      h('div', { class: 'grid cols-4' }, [1, 2, 3, 4].map(() => h('div', { class: 'glass stat' }, skeletonBlock(64)))));

    const [overview, activity] = await Promise.all([loadOverview(), api('activity?days=14')]);
    const tables = overview.tables;
    const failing = overview.verification && overview.verification.tables.find((t) => !t.isValid && t.table);
    if (!state.chainTable || !tables.some((t) => t.table === state.chainTable) || (failing && !state.chainPicked)) {
      state.chainTable = (failing && failing.table) || (tables.slice().sort((a, b) => b.records - a.records)[0] || {}).table || null;
    }

    const lastEntry = tables.reduce((latest, t) => (t.lastEntryUtc && (!latest || t.lastEntryUtc > latest) ? t.lastEntryUtc : latest), null);
    view.replaceChildren(
      heroCard(),
      h('div', { class: 'grid cols-4' },
        statTile('Audited tables', number.format(overview.totals.tables), 'grid', 'var(--blue)', 'with a hash chain each'),
        statTile('Entries', number.format(overview.totals.records), 'list', 'var(--indigo)', 'sealed with HMAC-SHA256'),
        statTile('Users', number.format(overview.totals.users), 'user', 'var(--teal)', 'attributed changes'),
        statTile('Last entry', lastEntry ? relTime(lastEntry) : '—', 'clock', 'var(--orange)', lastEntry ? dateTime.format(new Date(lastEntry)) : 'nothing audited yet')),
      h('div', { class: 'grid split' }, chainCard(), activityCard(activity)),
      tables.length ? h('div', { class: 'grid cols-3' }, tables.map(tableCard)) : emptyCard());
    await loadChain();
  }

  function statTile(label, value, iconName, tint, hint) {
    return h('div', { class: 'glass stat', style: { '--tint': tint } },
      h('div', { class: 'label' }, icon(iconName), h('span', { text: label })),
      h('div', { class: 'value', text: value }),
      h('div', { class: 'hint', text: hint }));
  }

  function emptyCard() {
    return h('div', { class: 'glass card' }, h('div', { class: 'empty' }, icon('shield'),
      h('strong', { text: 'Nothing has been audited yet' }),
      h('p', { text: 'Save a change through your DbContext and it will appear here, sealed into the hash chain.' })));
  }

  function heroCard() {
    const verification = state.overview.verification;
    let kind = 'idle', title = 'Not verified yet', text = 'Run a verification to check every hash chain, the signed chain heads and any anchors you provide.', iconName = 'shield';
    if (state.verifying) {
      kind = 'run'; title = 'Verifying…'; text = 'Recomputing every hash with the secret key and following the chain.'; iconName = 'refresh';
    } else if (verification && verification.isValid) {
      kind = 'ok'; title = 'Audit trail intact'; iconName = 'shield-check';
      text = `${plural(verification.recordsChecked, 'entry', 'entries')} across ${plural(verification.tables.length, 'table', 'tables')} verified ${relTime(verification.completedUtc)}. No entry was changed, removed or inserted.`;
    } else if (verification) {
      kind = 'bad'; title = 'Tampering suspected'; iconName = 'shield-alert';
      const failed = verification.tables.find((t) => !t.isValid);
      text = failed ? explain(failed) : verification.message;
    }

    const meta = [];
    if (verification && !state.verifying) {
      meta.push(h('span', { class: 'pill idle' }, icon('clock', 'ic-s'), verification.source === 'background' ? 'Scheduled check' : 'Manual check'));
      for (const failed of verification.tables.filter((t) => !t.isValid)) {
        meta.push(h('span', { class: 'pill bad', text: failed.table ? `${failed.table}: ${failed.failure}` : failed.failure }));
      }
      const anchors = verification.tables.reduce((sum, t) => sum + (t.anchorsMatched || 0), 0);
      if (anchors) meta.push(h('span', { class: 'pill accent' }, icon('anchor', 'ic-s'), `${plural(anchors, 'anchor', 'anchors')} matched`));
    }

    return h('section', { class: 'glass hero ' + kind, 'aria-label': 'Integrity status' },
      h('div', { class: 'glow' }),
      h('div', { class: 'orb' }, icon(iconName)),
      h('div', { class: 'hero-body' }, h('h2', { text: title }), h('p', { text: text }), meta.length ? h('div', { class: 'hero-meta' }, meta) : null),
      h('div', { class: 'hero-actions' },
        state.overview.capabilities.verify
          ? h('button', { class: 'btn primary', type: 'button', onclick: () => runVerification(), disabled: state.verifying }, icon('verify'), h('span', { text: 'Verify now' }))
          : null,
        h('a', { class: 'btn', href: '#/trail' }, icon('list'), h('span', { text: 'Browse the trail' }))));
  }

  // Hash chain visual ---------------------------------------------------------
  function chainCard() {
    const tables = state.overview.tables;
    const picker = tables.length > 1 ? tablePicker(tables.map((t) => t.table), state.chainTable, (value) => { state.chainTable = value; state.chainPicked = true; loadChain(); }) : null;
    return h('section', { class: 'glass card', id: 'chain-card', 'aria-label': 'Hash chain' },
      h('div', { class: 'card-head' }, h('h2', null, icon('link'), 'Hash chain'), picker),
      h('p', { class: 'card-sub', text: 'Every entry stores the hash of the one before it. Change, remove or insert anything and the chain breaks.' }),
      h('div', { class: 'chain-scroll', id: 'chain-host' }, skeletonBlock(150)),
      h('div', { class: 'hero-meta', id: 'chain-meta' }));
  }

  function tablePicker(names, selected, onChange) {
    if (names.length <= 4) {
      const group = h('div', { class: 'segmented', role: 'group', 'aria-label': 'Table' });
      names.forEach((name) => group.append(h('button', {
        type: 'button', 'aria-pressed': String(name === selected), text: name,
        onclick: (event) => {
          $$('button', group).forEach((b) => b.setAttribute('aria-pressed', String(b === event.currentTarget)));
          onChange(name);
        }
      })));
      return group;
    }
    const select = h('select', { class: 'field', 'aria-label': 'Table', onchange: (e) => onChange(e.target.value) },
      names.map((name) => h('option', { value: name, text: name, selected: name === selected })));
    return select;
  }

  async function loadChain() {
    const host = $('#chain-host');
    if (!host) return;
    const table = state.chainTable;
    if (!table) { host.replaceChildren(h('p', { class: 'muted', text: 'No audited tables yet.' })); return; }

    const failure = failedSequence(table);
    const info = state.overview.tables.find((t) => t.table === table);
    let query = 'logs?pageSize=7&table=' + encodeURIComponent(table);
    if (failure !== null && info && failure < info.lastSequence - 5) {
      // Show the neighbourhood of the broken entry instead of the end of the chain.
      const from = Math.max(1, failure - 3);
      query += `&seqFrom=${from}&seqTo=${from + 6}`;
    }
    const data = await api(query);
    const entries = data.items.slice().reverse();

    const chain = h('div', { class: 'chain', role: 'list' });
    entries.forEach((entry, index) => {
      const broken = failure !== null && entry.sequence === failure;
      const isHead = info ? entry.sequence === info.lastSequence : index === entries.length - 1;
      if (index > 0) chain.append(h('div', { class: 'link' + (broken ? ' broken' : ''), 'aria-hidden': 'true' }, icon('link')));
      chain.append(h('button', {
        class: 'block' + (isHead ? ' head' : '') + (broken ? ' broken' : ''), type: 'button', role: 'listitem', style: { '--i': index },
        title: `Open entry #${entry.sequence}`, onclick: () => openDrawer(entry)
      },
        isHead ? h('span', { class: 'head-badge', text: 'HEAD' }) : null,
        h('div', { class: 'top' }, h('span', { class: 'seq', text: '#' + entry.sequence }), actionPill(entry.action)),
        h('div', { class: 'rec', text: entry.recordId, title: entry.recordId }),
        h('div', { class: 'hash mono' }, icon('hash'), h('span', { text: shortHash(entry.currentHash) })),
        h('div', { class: 'foot' }, userChip(entry.userId), h('span', { text: relTime(entry.timestampUtc) }))));
    });
    host.replaceChildren(entries.length ? chain : h('p', { class: 'muted', text: 'This table has no entries.' }));
    host.scrollLeft = host.scrollWidth;
    const hint = () => host.classList.toggle('has-more', host.scrollLeft > 4);
    host.onscroll = hint;
    hint();

    const meta = $('#chain-meta');
    meta.replaceChildren();
    if (info) {
      meta.append(
        h('span', { class: 'pill ' + (info.headAuthenticated ? 'ok' : 'idle') }, icon(info.headAuthenticated ? 'shield-check' : 'shield', 'ic-s'), info.headAuthenticated ? 'Chain head signed' : 'Chain head unsigned (legacy)'),
        h('span', { class: 'pill idle', text: `${plural(info.unanchoredCount, 'entry', 'entries')} since the last anchor` }));
    }
  }

  function failedSequence(table) {
    const verification = state.overview.verification;
    const result = verification && verification.tables.find((t) => t.table === table && !t.isValid);
    return result && result.failedSequence ? result.failedSequence : null;
  }

  // Activity chart ------------------------------------------------------------
  function activityCard(activity) {
    const width = 640, height = 210, top = 14, bottom = 30, left = 4;
    const series = activity.series;
    const totals = series.map((d) => ACTIONS.reduce((sum, [, key]) => sum + d[key], 0));
    const max = Math.max(4, ...totals);
    const step = (width - left) / series.length;
    const barWidth = Math.min(30, step * 0.62);
    const plot = height - top - bottom;

    const svg = s('svg', { class: 'chart', viewBox: `0 0 ${width} ${height}`, role: 'img', 'aria-label': 'Entries per day' });
    for (let i = 0; i <= 3; i++) {
      const y = top + plot - (plot * i) / 3;
      svg.append(s('line', { class: 'grid-line', x1: left, x2: width, y1: y, y2: y }));
      if (i > 0) svg.append(s('text', { x: left, y: y - 4 }, String(Math.round((max * i) / 3))));
    }
    series.forEach((day, index) => {
      const x = left + index * step + (step - barWidth) / 2;
      let y = top + plot;
      const group = s('g', { class: 'bar-group' });
      const date = new Date(day.date + 'T00:00:00Z');
      group.append(s('title', null, `${dateShort.format(date)}: ${totals[index]} ${totals[index] === 1 ? 'entry' : 'entries'}`));
      for (const [, key, color] of ACTIONS) {
        const value = day[key];
        if (!value) continue;
        const barHeight = Math.max(3, (value / max) * plot);
        y -= barHeight;
        group.append(s('rect', { class: 'bar', x, y, width: barWidth, height: barHeight, rx: Math.min(7, barWidth / 3), style: { fill: color } }));
      }
      if (index % Math.ceil(series.length / 7) === 0 || index === series.length - 1) {
        group.append(s('text', { x: x + barWidth / 2, y: height - 7, 'text-anchor': 'middle' }, series.length <= 8 ? weekday.format(date) : dateShort.format(date)));
      }
      svg.append(group);
    });

    return h('section', { class: 'glass card', 'aria-label': 'Activity' },
      h('div', { class: 'card-head' }, h('h2', null, icon('clock'), 'Activity'), h('span', { class: 'card-sub', text: 'Last 14 days' })),
      svg,
      h('div', { class: 'legend' }, ACTIONS.map(([label, , color]) => h('span', { style: { '--c': color } }, h('i'), label))));
  }

  function tableCard(table) {
    const status = tableStatus(table.table);
    return h('a', { class: 'glass table-card', href: '#/trail?table=' + encodeURIComponent(table.table) },
      h('div', { class: 'row' }, h('i', { class: 'dot ' + status }), h('h3', { text: table.table, title: table.table }),
        h('span', { class: 'pill ' + (status === 'ok' ? 'ok' : status === 'bad' ? 'bad' : 'idle'), text: status === 'ok' ? 'Intact' : status === 'bad' ? 'Broken' : 'Unchecked' })),
      h('dl', { class: 'kv' },
        h('dt', { text: 'Entries' }), h('dd', { text: number.format(table.records) }),
        h('dt', { text: 'Head' }), h('dd', { class: 'mono', text: shortHash(table.headHash) }),
        h('dt', { text: 'Last entry' }), h('dd', { text: table.lastEntryUtc ? relTime(table.lastEntryUtc) : '—' })));
  }

  // -------------------------------------------------------------------- trail
  async function renderTrail(params) {
    const t = state.trail;
    t.table = params.get('table') || '';
    t.action = (params.get('action') || '').split(',').filter(Boolean);
    t.user = params.get('user') || '';
    t.recordId = params.get('recordId') || '';
    t.from = params.get('from') || '';
    t.to = params.get('to') || '';
    t.q = params.get('q') || '';
    t.page = Math.max(1, parseInt(params.get('page') || '1', 10) || 1);
    $('#search').value = t.q;

    if (!state.overview) await loadOverview();

    const select = h('select', { class: 'field', id: 'f-table', 'aria-label': 'Table' },
      h('option', { value: '', text: 'All tables' }),
      state.overview.tables.map((x) => h('option', { value: x.table, text: x.table, selected: x.table === t.table })));
    const chips = h('div', { class: 'chips', role: 'group', 'aria-label': 'Actions' }, ACTIONS.map(([label, , color]) => h('button', {
      class: 'chip', type: 'button', 'aria-pressed': String(t.action.includes(label)), style: { '--tint': color }, 'data-action': label,
      onclick: (e) => { const on = e.currentTarget.getAttribute('aria-pressed') !== 'true'; e.currentTarget.setAttribute('aria-pressed', String(on)); applyFilters(); }
    }, h('i', { class: 'dot' }), label)));

    const text = (id, label, value, placeholder, type = 'text') => h('label', { class: 'field-label grow' }, label,
      h('input', { class: 'field', id, type, value, placeholder, autocomplete: 'off', spellcheck: 'false', oninput: debounced(applyFilters, 350), onchange: applyFilters }));

    const filters = h('section', { class: 'glass card', 'aria-label': 'Filters' },
      h('div', { class: 'filters' },
        h('label', { class: 'field-label grow' }, 'Table', select),
        text('f-user', 'User', t.user, 'e.g. alice'),
        text('f-record', 'Record id', t.recordId, 'e.g. 42'),
        text('f-from', 'From', t.from, '', 'date'),
        text('f-to', 'To', t.to, '', 'date'),
        h('button', { class: 'btn', type: 'button', onclick: () => navigate('#/trail') }, icon('x'), h('span', { text: 'Reset' }))),
      chips);
    select.addEventListener('change', applyFilters);

    const results = h('section', { class: 'glass card', id: 'trail-results', 'aria-label': 'Entries', style: { padding: '8px 6px 18px' } });
    view.replaceChildren(filters, results);
    await loadTrail();
  }

  function debounced(fn, ms) {
    let timer;
    return (...args) => { clearTimeout(timer); timer = setTimeout(() => fn(...args), ms); };
  }

  function currentFilters() {
    return {
      table: $('#f-table') ? $('#f-table').value : '',
      action: $$('.chip[aria-pressed="true"]').map((c) => c.dataset.action),
      user: $('#f-user') ? $('#f-user').value.trim() : '',
      recordId: $('#f-record') ? $('#f-record').value.trim() : '',
      from: $('#f-from') ? $('#f-from').value : '',
      to: $('#f-to') ? $('#f-to').value : '',
      q: $('#search').value.trim()
    };
  }

  function trailQuery(filters, page, pageSize) {
    const q = new URLSearchParams();
    if (filters.table) q.set('table', filters.table);
    if (filters.action.length) q.set('action', filters.action.join(','));
    if (filters.user) q.set('user', filters.user);
    if (filters.recordId) q.set('recordId', filters.recordId);
    if (filters.from) q.set('from', filters.from);
    if (filters.to) q.set('to', filters.to + 'T23:59:59.9999999');
    if (filters.q) q.set('q', filters.q);
    if (page) q.set('page', page);
    if (pageSize) q.set('pageSize', pageSize);
    return q;
  }

  function applyFilters() {
    Object.assign(state.trail, currentFilters(), { page: 1 });
    syncUrl();
    loadTrail();
  }

  function syncUrl() {
    const t = state.trail;
    const q = new URLSearchParams();
    if (t.table) q.set('table', t.table);
    if (t.action.length) q.set('action', t.action.join(','));
    if (t.user) q.set('user', t.user);
    if (t.recordId) q.set('recordId', t.recordId);
    if (t.from) q.set('from', t.from);
    if (t.to) q.set('to', t.to);
    if (t.q) q.set('q', t.q);
    if (t.page > 1) q.set('page', t.page);
    const suffix = q.toString();
    history.replaceState(null, '', '#/trail' + (suffix ? '?' + suffix : ''));
  }

  async function loadTrail() {
    const host = $('#trail-results');
    if (!host) return;
    const t = state.trail;
    host.replaceChildren(...[0, 1, 2, 3, 4].map(() => h('div', { style: { padding: '8px 16px' } }, skeletonBlock(36))));

    const data = await api('logs?' + trailQuery(t, t.page, t.pageSize));
    if (!data.items.length) {
      host.replaceChildren(h('div', { class: 'empty' }, icon('search'), h('strong', { text: 'No entries match' }), h('p', { text: 'Try removing a filter or widening the date range.' })));
      return;
    }

    const rows = data.items.map((entry) => h('button', { class: 'row-item', type: 'button', onclick: () => openDrawer(entry), title: 'Open entry' },
      h('span', { class: 'cell c-when when' }, relTime(entry.timestampUtc), h('small', { text: dateTime.format(new Date(entry.timestampUtc)) })),
      h('span', { class: 'cell c-table', text: entry.table }),
      h('span', { class: 'cell c-rec', text: entry.recordId }),
      h('span', { class: 'cell c-act' }, actionPill(entry.action)),
      h('span', { class: 'cell c-user' }, userChip(entry.userId)),
      h('span', { class: 'cell c-seq seq', text: '#' + entry.sequence }),
      h('span', { class: 'cell c-hash hashcell mono' }, shortHash(entry.currentHash))));

    const first = (data.page - 1) * data.pageSize + 1;
    const last = first + data.items.length - 1;
    const pages = Math.max(1, Math.ceil(data.total / data.pageSize));
    const go = (page) => { t.page = page; syncUrl(); loadTrail(); host.scrollIntoView({ behavior: 'smooth', block: 'start' }); };

    host.replaceChildren(
      h('div', { class: 'list-head' },
        h('span', { text: 'When' }), h('span', { class: 'c-table', text: 'Table' }), h('span', { text: 'Record' }), h('span', { text: 'Action' }),
        h('span', { text: 'User' }), h('span', { class: 'c-seq', text: 'Seq' }), h('span', { class: 'c-hash', text: 'Hash' })),
      h('div', { class: 'list', role: 'list' }, rows),
      h('div', { class: 'pager' },
        h('span', { text: `Showing ${number.format(first)}–${number.format(last)} of ${number.format(data.total)}` }),
        h('div', { class: 'btns' },
          h('button', { class: 'btn small', type: 'button', disabled: data.page <= 1, onclick: () => go(data.page - 1) }, icon('chev-left'), h('span', { text: 'Newer' })),
          h('span', { class: 'muted', style: { alignSelf: 'center' }, text: `${data.page} / ${pages}` }),
          h('button', { class: 'btn small', type: 'button', disabled: data.page >= pages, onclick: () => go(data.page + 1) }, h('span', { text: 'Older' }), icon('chev-right')))));
  }

  // ------------------------------------------------------------------- drawer
  const drawer = $('#drawer');
  const scrim = $('#scrim');
  let drawerReturnFocus = null;
  drawer.inert = true;

  function openDrawer(entry) {
    drawerReturnFocus = document.activeElement;
    const oldValues = parseJson(entry.oldValues);
    const newValues = parseJson(entry.newValues);

    drawer.replaceChildren(
      h('div', { class: 'drawer-head' },
        h('h2', { text: `${entry.table} · ${entry.recordId}` }),
        actionPill(entry.action),
        h('button', { class: 'icon-btn', type: 'button', 'aria-label': 'Close', onclick: closeDrawer }, icon('x'))),
      h('div', { class: 'drawer-body' },
        h('section', null, h('div', { class: 'meta' },
          metaItem('clock', 'When', dateTime.format(new Date(entry.timestampUtc))),
          metaItem('user', 'User', userChip(entry.userId)),
          metaItem('table', 'Table', entry.table),
          metaItem('hash', 'Sequence', '#' + number.format(entry.sequence)),
          metaItem('key', 'Key', entry.keyId || 'default'),
          metaItem('shield', 'Hash format', entry.hashVersion === 0 ? 'Legacy (1.x)' : 'Canonical v' + entry.hashVersion))),
        h('section', null, h('h3', { text: 'Changes' }), diffView(entry.action, oldValues, newValues)),
        h('section', null, h('h3', { text: 'Hash chain' }),
          h('div', { class: 'hashbox' },
            hashRow('Previous', entry.previousHash),
            h('div', { class: 'join' }, icon('link')),
            hashRow('This entry', entry.currentHash))),
        h('details', { class: 'fold' }, h('summary', { text: 'Raw values' }),
          h('pre', { class: 'raw', text: JSON.stringify({ oldValues, newValues }, null, 2) })),
        h('div', { style: { display: 'flex', gap: '10px', flexWrap: 'wrap' } },
          h('a', { class: 'btn small', href: '#/trail?table=' + encodeURIComponent(entry.table) + '&recordId=' + encodeURIComponent(entry.recordId), onclick: () => closeDrawer() }, icon('list'), h('span', { text: 'History of this record' })))));

    drawer.inert = false;
    drawer.setAttribute('aria-hidden', 'false');
    scrim.hidden = false;
    requestAnimationFrame(() => { drawer.classList.add('open'); drawer.focus({ preventScroll: true }); });
  }

  function closeDrawer() {
    if (!drawer.classList.contains('open')) return;
    drawer.classList.remove('open');
    drawer.setAttribute('aria-hidden', 'true');
    drawer.inert = true;
    scrim.hidden = true;
    if (drawerReturnFocus && document.contains(drawerReturnFocus)) drawerReturnFocus.focus({ preventScroll: true });
  }

  scrim.addEventListener('click', closeDrawer);

  const metaItem = (iconName, label, value) => h('div', null, h('div', { class: 'k' }, icon(iconName), label), h('div', { class: 'v' }, value));

  function hashRow(label, hash) {
    return h('div', { class: 'hrow' }, h('span', { class: 'lbl', text: label }), h('span', { class: 'val', text: hash }),
      h('button', { class: 'copy', type: 'button', 'aria-label': 'Copy hash', onclick: () => copy(hash, 'Hash copied') }, icon('copy')));
  }

  function parseJson(text) {
    if (!text) return null;
    try { return JSON.parse(text); } catch { return text; }
  }

  function valueNode(value) {
    if (value === null || value === undefined) return h('span', { class: 'faint', text: 'null' });
    if (typeof value === 'string' && /^\[MASKED:[0-9a-f]{8}\]$/.test(value)) return h('span', { class: 'masked', title: 'Stored as a keyed fingerprint, never as clear text', text: value });
    if (typeof value === 'object') return h('span', { class: 'mono', text: JSON.stringify(value) });
    const text = String(value);
    return h('span', { text: text.length > 400 ? text.slice(0, 400) + '…' : text, title: text.length > 400 ? text : null });
  }

  function diffView(action, oldValues, newValues) {
    const isObject = (v) => v && typeof v === 'object' && !Array.isArray(v);
    if (!isObject(oldValues) && !isObject(newValues)) return h('p', { class: 'muted', text: 'No values were recorded for this entry.' });

    if (isObject(oldValues) && isObject(newValues)) {
      const keys = Array.from(new Set([...Object.keys(oldValues), ...Object.keys(newValues)])).sort();
      return h('div', { class: 'diff', role: 'table' }, keys.map((key) => h('div', { class: 'diff-row', role: 'row' },
        h('span', { class: 'prop', text: key }),
        h('span', { class: 'old' }, key in oldValues ? valueNode(oldValues[key]) : h('span', { class: 'none', text: '—' })),
        h('span', { class: 'new' }, key in newValues ? valueNode(newValues[key]) : h('span', { class: 'none', text: '—' })))));
    }

    const values = isObject(newValues) ? newValues : oldValues;
    const cls = isObject(newValues) ? 'new' : 'old';
    return h('div', { class: 'diff single', role: 'table' }, Object.keys(values).sort().map((key) => h('div', { class: 'diff-row', role: 'row' },
      h('span', { class: 'prop', text: key }), h('span', { class: cls }, valueNode(values[key])))));
  }

  // ------------------------------------------------------------------- verify
  async function runVerification(options = {}) {
    if (state.verifying) return null;
    state.verifying = true;
    const button = $('#verify-all');
    button.classList.add('busy'); button.disabled = true;
    refreshHero();
    try {
      const report = await api('verify', { method: 'POST', body: { table: options.table || null, anchors: options.anchors || null } });
      if (!options.table) {
        state.overview.verification = report;
      } else if (state.overview.verification) {
        const others = state.overview.verification.tables.filter((t) => t.table !== options.table);
        const combined = others.concat(report.tables);
        state.overview.verification = Object.assign({}, report, { isValid: combined.every((t) => t.isValid), tables: combined });
      } else {
        state.overview.verification = report;
      }
      toast(report.isValid ? 'Audit trail verified — nothing was tampered with' : 'Tampering suspected — see the details', report.isValid ? 'ok' : 'bad');
      return report;
    } catch (error) {
      toast(error.message, 'bad');
      return null;
    } finally {
      state.verifying = false;
      button.classList.remove('busy'); button.disabled = false;
      renderSidebarTables();
      refreshHero();
    }
  }

  function refreshHero() {
    const hero = $('.hero');
    if (hero && state.overview) hero.replaceWith(heroCard());
    if (!$('#chain-host') || !state.overview) return;

    // A table that failed verification is the interesting one: show its chain unless the user picked another.
    const verification = state.overview.verification;
    const failing = verification && !state.verifying && verification.tables.find((t) => !t.isValid && t.table);
    if (failing && !state.chainPicked && state.chainTable !== failing.table) {
      state.chainTable = failing.table;
      $('#chain-card').replaceWith(chainCard());
    }
    loadChain();
  }

  function renderVerify() {
    const tables = state.overview.tables;
    const canVerify = state.overview.capabilities.verify;
    const select = h('select', { class: 'field', id: 'v-table', 'aria-label': 'Table' }, h('option', { value: '', text: 'All tables' }), tables.map((t) => h('option', { value: t.table, text: t.table })));
    const anchors = h('textarea', { class: 'field', id: 'v-anchors', placeholder: 'Paste anchor e-mails or hashes here (one per line, or whole messages)…', spellcheck: 'false', 'aria-label': 'Anchors' });
    const results = h('div', { id: 'v-results', style: { display: 'flex', flexDirection: 'column', gap: '12px' } });

    const run = h('button', { class: 'btn primary', type: 'button', disabled: !canVerify, onclick: async () => {
      const report = await runVerification({ table: select.value || null, anchors: anchors.value });
      if (report) showResults(results, report);
    } }, icon('verify'), h('span', { text: 'Run verification' }));

    view.replaceChildren(
      h('div', { class: 'grid split' },
        h('section', { class: 'glass card' },
          h('div', { class: 'card-head' }, h('h2', null, icon('verify'), 'Verify integrity')),
          canVerify ? null : h('p', { class: 'pill bad', text: 'The secret key is not available to the dashboard: register it with AddTamperEvident(...).' }),
          h('label', { class: 'field-label' }, 'Table', select),
          h('label', { class: 'field-label' }, h('span', null, 'Anchors ', h('span', { class: 'faint', text: '(optional)' })), anchors),
          h('p', { class: 'card-sub', text: 'Anchors are chain hashes that were stored outside the database (e-mail, webhook, file). If someone rewrote the history, they will not be found.' }),
          h('div', { style: { display: 'flex', gap: '10px' } }, run)),
        h('section', { class: 'glass card' },
          h('div', { class: 'card-head' }, h('h2', null, icon('shield-check'), 'What is checked')),
          h('ol', { class: 'steps' },
            step('link', 'Every link', 'Each entry must point to the hash of its predecessor.'),
            step('hash', 'Every hash', 'All fields, the user and the timestamp are recomputed with the secret key (HMAC-SHA256).'),
            step('key', 'The chain head', 'The signed head exposes entries that were deleted from the end of the chain.'),
            step('anchor', 'Your anchors', 'Hashes stored elsewhere must still occur in the chain.')))),
      state.overview.verification ? (showResults(results, state.overview.verification), results) : results);
  }

  const step = (iconName, title, text) => h('li', null, icon(iconName), h('span', null, h('strong', { text: title }), text));

  function showResults(host, report) {
    const header = h('div', { class: 'result ' + (report.isValid ? 'ok' : 'bad'), style: { '--i': 0 } },
      h('div', { class: 'badge' }, icon(report.isValid ? 'shield-check' : 'shield-alert')),
      h('div', { class: 'body' },
        h('div', { class: 'title' }, report.isValid ? 'Everything checks out' : 'Tampering suspected'),
        h('div', { class: 'msg', text: report.message }),
        h('div', { class: 'metrics' },
          h('span', { class: 'pill idle', text: `${plural(report.recordsChecked, 'entry', 'entries')} checked` }),
          h('span', { class: 'pill idle', text: relTime(report.completedUtc) }))));

    const items = report.tables.map((t, i) => h('div', { class: 'result ' + (t.isValid ? 'ok' : 'bad'), style: { '--i': i + 1 } },
      h('div', { class: 'badge' }, icon(t.isValid ? 'check' : 'x')),
      h('div', { class: 'body' },
        h('div', { class: 'title' }, t.table || 'Anchors', h('span', { class: 'pill ' + (t.isValid ? 'ok' : 'bad'), text: t.isValid ? 'Intact' : t.failure })),
        h('div', { class: 'msg', text: t.isValid ? t.message : explain(t) }),
        t.isValid ? null : h('div', { class: 'msg faint mono', text: t.message }),
        h('div', { class: 'metrics' },
          h('span', { class: 'pill idle', text: `${plural(t.recordsChecked, 'entry', 'entries')}` }),
          t.anchorsMatched ? h('span', { class: 'pill accent', text: `${plural(t.anchorsMatched, 'anchor', 'anchors')} matched` }) : null,
          t.failedSequence ? h('span', { class: 'pill bad', text: `Failed at entry #${t.failedSequence}` }) : null,
          h('span', { class: 'pill idle', text: `${t.durationMs} ms` })))));
    host.replaceChildren(header, ...items);
  }

  // ------------------------------------------------------------------- export
  function renderExport() {
    const tables = state.overview.tables;
    const canVerify = state.overview.capabilities.verify;
    const select = h('select', { class: 'field', id: 'x-table', 'aria-label': 'Table', onchange: update }, h('option', { value: '', text: 'All tables' }), tables.map((t) => h('option', { value: t.table, text: t.table })));
    const from = h('input', { class: 'field', id: 'x-from', type: 'date', onchange: update, 'aria-label': 'From' });
    const to = h('input', { class: 'field', id: 'x-to', type: 'date', onchange: update, 'aria-label': 'To' });
    const links = {};

    function href(format) {
      const q = new URLSearchParams({ format });
      if (select.value) q.set('table', select.value);
      if (from.value) q.set('from', from.value);
      if (to.value) q.set('to', to.value + 'T23:59:59.9999999');
      return 'api/export?' + q;
    }

    function update() { for (const [format, link] of Object.entries(links)) link.setAttribute('href', href(format)); }

    const option = (format, tint, iconName, title, text, disabled = false) => {
      links[format] = h('a', { class: 'btn' + (disabled ? ' ' : ' primary'), href: href(format), download: '', 'aria-disabled': disabled ? 'true' : null, style: disabled ? { opacity: 0.5, pointerEvents: 'none' } : null }, icon('export'), h('span', { text: 'Download' }));
      return h('div', { class: 'glass option', style: { '--tint': tint } }, h('div', { class: 'glyph' }, icon(iconName)), h('h3', { text: title }), h('p', { text: text }), links[format]);
    };

    view.replaceChildren(
      h('section', { class: 'glass card' },
        h('div', { class: 'card-head' }, h('h2', null, icon('export'), 'Export the audit trail')),
        h('p', { class: 'card-sub', text: 'Choose what to include. Large exports are streamed, so the browser never has to hold them in memory.' }),
        h('div', { class: 'filters' }, h('label', { class: 'field-label grow' }, 'Table', select), h('label', { class: 'field-label grow' }, 'From', from), h('label', { class: 'field-label grow' }, 'To', to))),
      h('div', { class: 'grid cols-3' },
        option('csv', 'var(--green)', 'table', 'CSV', 'A spreadsheet-friendly list of entries. Cells that could be read as formulas are neutralised.'),
        option('jsonl', 'var(--blue)', 'braces', 'JSON Lines', 'One JSON object per entry, in chain order. Ideal for archives, SIEMs and scripts.'),
        option('evidence', 'var(--indigo)', 'shield-check', 'Evidence bundle', 'Every entry in chain order together with the verification result, ready to hand to an auditor.', !canVerify)));
  }

  // -------------------------------------------------------------- global bits
  $('#verify-all').addEventListener('click', () => {
    if (!state.overview || !state.overview.capabilities.verify) { toast('Verification is not configured on the server', 'bad'); return; }
    runVerification().then((report) => { if (report && $('#v-results')) showResults($('#v-results'), report); });
  });

  $('#search').addEventListener('keydown', (event) => {
    if (event.key !== 'Enter') return;
    const q = event.target.value.trim();
    state.trail = Object.assign(state.trail, { q, page: 1 });
    navigate('#/trail' + (q ? '?q=' + encodeURIComponent(q) : ''));
  });

  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') closeDrawer();
    const typing = /^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement && document.activeElement.tagName);
    if (event.key === '/' && !typing && !event.metaKey && !event.ctrlKey) { event.preventDefault(); $('#search').focus(); }
  });

  // Theme ----------------------------------------------------------------------
  const root = document.documentElement;
  function effectiveTheme() {
    const explicit = root.dataset.theme;
    if (explicit === 'light' || explicit === 'dark') return explicit;
    return matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  }
  function paintThemeButton() {
    const dark = effectiveTheme() === 'dark';
    $('#theme-toggle use').setAttribute('href', dark ? '#i-sun' : '#i-moon');
  }
  const savedTheme = store.get('te-theme');
  if (savedTheme === 'light' || savedTheme === 'dark') root.dataset.theme = savedTheme;
  paintThemeButton();
  matchMedia('(prefers-color-scheme: dark)').addEventListener('change', paintThemeButton);
  $('#theme-toggle').addEventListener('click', () => {
    const next = effectiveTheme() === 'dark' ? 'light' : 'dark';
    root.dataset.theme = next;
    store.set('te-theme', next);
    paintThemeButton();
  });

  // Light that follows the pointer over glass surfaces ---------------------------
  let sheenFrame = 0;
  document.addEventListener('pointermove', (event) => {
    if (sheenFrame) return;
    const target = event.target instanceof Element ? event.target.closest('.glass') : null;
    if (!target) return;
    sheenFrame = requestAnimationFrame(() => {
      sheenFrame = 0;
      const rect = target.getBoundingClientRect();
      target.style.setProperty('--mx', `${event.clientX - rect.left}px`);
      target.style.setProperty('--my', `${event.clientY - rect.top}px`);
    });
  }, { passive: true });

  window.addEventListener('hashchange', render);
  render();
})();
