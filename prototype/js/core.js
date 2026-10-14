/* CloudOps Console prototype – core: state, router, UI helpers, SVG charts */
(function () {
  'use strict';
  class Raw { constructor(s) { this.s = s; } }
  const raw = s => new Raw(String(s));
  const esc = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const val = v => v == null || v === false ? '' : v instanceof Raw ? v.s : Array.isArray(v) ? v.map(val).join('') : esc(v);
  // tagged template: interpolations are HTML-escaped unless they are nested h`` / raw()
  const h = (strs, ...vals) => { let o = strs[0]; vals.forEach((v, i) => { o += val(v) + strs[i + 1]; }); return new Raw(o); };

  const ROLES = ['Platform Admin', 'Cloud Engineer', 'Ops/SRE', 'Client Viewer', 'Auditor'];
  const TENANTS = ['All tenants', 'Acme Bank', 'Globex Retail', 'Initech Health', 'IBM Internal'];
  const COC = window.COC = {
    h, raw, esc, ROLES, TENANTS, modules: [], actions: {}, inputs: {}, data: {}, auditLog: [],
    state: { role: ROLES[0], tenant: TENANTS[0], theme: 'dark' },
  };

  // deterministic RNG so the dummy data is stable between reloads
  COC.rng = seed => () => { seed |= 0; seed = seed + 0x6D2B79F5 | 0; let t = Math.imul(seed ^ seed >>> 15, 1 | seed); t = t + Math.imul(t ^ t >>> 7, 61 | t) ^ t; return ((t ^ t >>> 14) >>> 0) / 4294967296; };
  COC.pick = (r, a) => a[Math.floor(r() * a.length)];

  COC.register = m => COC.modules.push(m);
  COC.can = () => ['Platform Admin', 'Cloud Engineer', 'Ops/SRE'].includes(COC.state.role);
  COC.byTenant = arr => COC.state.tenant === TENANTS[0] ? arr : arr.filter(x => !x.tenant || x.tenant === COC.state.tenant);
  COC.audit = (action, target) => COC.auditLog.unshift({ t: new Date(), user: 'jayant@coc.local', role: COC.state.role, tenant: COC.state.tenant, action, target: target || '' });

  /* ---------- toast / modal ---------- */
  COC.toast = (msg, kind) => {
    const el = document.createElement('div'); el.className = 'toast ' + (kind || ''); el.textContent = msg;
    document.getElementById('toasts').appendChild(el); setTimeout(() => el.remove(), 3800);
  };
  COC.modal = ({ title, body, wide, actions }) => {
    const ov = document.getElementById('overlay');
    COC._modalActions = actions || [{ label: 'Close' }];
    ov.innerHTML = h`<div class="modal ${wide ? 'wide' : ''}" role="dialog" aria-modal="true" aria-label="${title}">
      <header>${title}<button class="btn s" data-act="modal.close">✕</button></header>
      <div class="bd">${body}</div>
      <footer>${COC._modalActions.map((a, i) => h`<button class="btn ${a.primary ? 'p' : ''} ${a.danger ? 'd' : ''}" data-act="modal.do" data-arg="${i}">${a.label}</button>`)}</footer></div>`.s;
    const f = ov.querySelector('input,select,textarea'); if (f) f.focus();
  };
  COC.closeModal = () => { document.getElementById('overlay').innerHTML = ''; COC._modalActions = null; };
  COC.actions['modal.close'] = () => COC.closeModal();
  COC.actions['modal.do'] = i => { const a = COC._modalActions[+i]; if (!a) return; if (a.fn && a.fn() === false) return; COC.closeModal(); };
  COC.v = id => { const e = document.getElementById(id); return e ? e.value : ''; };
  COC.confirm = (title, text, fn, danger) => COC.modal({ title, body: h`<p>${text}</p>`, actions: [{ label: 'Cancel' }, { label: 'Confirm', primary: !danger, danger, fn }] });

  /* ---------- UI components ---------- */
  const SEV = { critical: 'b-crit', high: 'b-bad', medium: 'b-warn', low: 'b-info', info: 'b-mut' };
  COC.ui = {
    badge: (t, k) => h`<span class="badge ${k ? 'b-' + k : ''}">${t}</span>`,
    sev: s => h`<span class="badge ${SEV[String(s).toLowerCase()] || ''}">${s}</span>`,
    dot: c => h`<span class="dot" style="background:${c}"></span>`,
    kpi: (l, v, d, dk) => h`<div class="card kpi"><div class="l">${l}</div><div class="v">${v}</div>${d != null ? h`<div class="d ${dk || 'mut'}">${d}</div>` : ''}</div>`,
    bar: (pct, kind) => h`<div class="bar ${kind || (pct > 85 ? 'bad' : pct > 70 ? 'warn' : 'ok')}"><i style="width:${Math.min(100, Math.max(0, pct))}%"></i></div>`,
    tabs: (id, tabs, cur) => h`<div class="tabs" role="tablist">${tabs.map(([k, l]) => h`<button role="tab" class="${k === cur ? 'on' : ''}" data-act="tab" data-arg="${id}:${k}">${l}</button>`)}</div>`,
    sw: (on, act, arg) => h`<label class="sw"><input type="checkbox" ${on ? 'checked' : ''} data-w data-chg="${act}" data-arg="${arg}"><span></span></label>`,
    btn: (label, act, arg, o) => { o = o || {}; return h`<button class="btn ${o.p ? 'p' : ''} ${o.d ? 'd' : ''} ${o.s ? 's' : ''}" data-act="${act}" data-arg="${arg == null ? '' : arg}" ${o.w ? raw('data-w') : ''}>${label}</button>`; },
    table: (cols, rows, o) => {
      o = o || {};
      if (!rows.length) return h`<div class="empty">${o.empty || 'Nothing to show.'}</div>`;
      return h`<div class="tw"><table class="tbl"><thead><tr>${cols.map(c => h`<th class="${c.num ? 'num' : ''}">${c.h}</th>`)}</tr></thead><tbody>${rows.map((r, i) => h`<tr class="${o.click ? 'click' : ''}" ${o.click ? raw(`data-act="${o.click}" data-arg="${esc(o.key ? o.key(r) : i)}"`) : ''}>${cols.map(c => h`<td class="${c.num ? 'num' : ''}">${c.f(r, i)}</td>`)}</tr>`)}</tbody></table></div>`;
    },
    select: (id, opts, cur, act, arg) => h`<select id="${id}" data-chg="${act}" data-arg="${arg || id}">${opts.map(o => { const [v, l] = Array.isArray(o) ? o : [o, o]; return h`<option value="${v}" ${String(v) === String(cur) ? raw('selected') : ''}>${l}</option>`; })}</select>`,
    pre: t => h`<pre class="code">${t}</pre>`,
    fmt$: n => '$' + Math.round(n).toLocaleString('en-US'),
    ago: m => m < 60 ? m + 'm ago' : m < 1440 ? Math.round(m / 60) + 'h ago' : Math.round(m / 1440) + 'd ago',
  };
  COC.cloudColor = { AWS: '#ff9900', Azure: '#2b8cff', GCP: '#34a853', OpenShift: '#ee3b3b', 'IBM Cloud': '#8a6dff' };
  COC.palette = ['#4589ff', '#08bdba', '#a56eff', '#f1c21b', '#fa4d56', '#42be65', '#ff7eb6', '#ff9900'];

  /* ---------- SVG charts (dependency-free) ---------- */
  COC.chart = {
    line(series, o) {
      o = Object.assign({ w: 640, h: 220, labels: [], fmt: v => v, marks: [], band: null }, o || {});
      const L = 44, R = 10, T = 10, B = 24, W = o.w, H = o.h, n = Math.max(...series.map(s => s.data.length));
      let all = series.flatMap(s => s.data.filter(v => v != null)); if (o.band) all = all.concat(o.band.hi, o.band.lo);
      const mn = o.min != null ? o.min : Math.min(0, ...all), mx = o.max != null ? o.max : Math.max(...all) * 1.08 || 1;
      const x = i => L + (W - L - R) * (n === 1 ? 0 : i / (n - 1)), y = v => T + (H - T - B) * (1 - (v - mn) / (mx - mn || 1));
      let s = `<svg viewBox="0 0 ${W} ${H}" width="100%" role="img" aria-label="${esc(o.title || 'chart')}"><g class="grid">`;
      for (let k = 0; k <= 4; k++) { const v = mn + (mx - mn) * k / 4, yy = y(v); s += `<line x1="${L}" x2="${W - R}" y1="${yy}" y2="${yy}"/><text x="${L - 6}" y="${yy + 3}" text-anchor="end">${esc(o.fmt(Math.round(v * 10) / 10))}</text>`; }
      s += '</g>';
      const step = Math.ceil(o.labels.length / 8) || 1;
      o.labels.forEach((l, i) => { if (i % step === 0) s += `<text x="${x(i)}" y="${H - 6}" text-anchor="middle">${esc(l)}</text>`; });
      if (o.band) { const up = o.band.hi.map((v, i) => `${x(i)},${y(v)}`), dn = o.band.lo.map((v, i) => `${x(i)},${y(v)}`).reverse(); s += `<polygon points="${up.concat(dn).join(' ')}" fill="#4589ff" opacity=".15"/>`; }
      series.forEach((se, k) => {
        const c = se.color || COC.palette[k % 8];
        const pts = se.data.map((v, i) => v == null ? null : `${x(i)},${y(v)}`).filter(Boolean);
        s += `<polyline fill="none" stroke="${c}" stroke-width="2" ${se.dash ? 'stroke-dasharray="5 4"' : ''} points="${pts.join(' ')}"/>`;
      });
      o.marks.forEach(m => { s += `<circle cx="${x(m.i)}" cy="${y(m.v)}" r="5" fill="var(--bad)" stroke="var(--panel)" stroke-width="2"><title>${esc(m.t || 'anomaly')}</title></circle>`; });
      if (o.vline != null) s += `<line x1="${x(o.vline)}" x2="${x(o.vline)}" y1="${T}" y2="${H - B}" stroke="var(--mut)" stroke-dasharray="3 3"/>`;
      if (o.hline != null) s += `<line x1="${L}" x2="${W - R}" y1="${y(o.hline)}" y2="${y(o.hline)}" stroke="var(--bad)" stroke-dasharray="4 3"/><text x="${W - R}" y="${y(o.hline) - 3}" text-anchor="end" style="fill:var(--bad)">${esc(o.hlabel || 'limit')}</text>`;
      s += '</svg>';
      const lg = series.length > 1 ? `<div class="legend">${series.map((se, k) => `<span><i style="background:${se.color || COC.palette[k % 8]}"></i>${esc(se.name)}</span>`).join('')}</div>` : '';
      return raw(s + lg);
    },
    bars(items, o) {
      o = Object.assign({ w: 520, fmt: v => v }, o || {});
      const max = Math.max(...items.map(i => i.value), 1), rh = 26, H = items.length * rh + 4, lw = 110;
      let s = `<svg viewBox="0 0 ${o.w} ${H}" width="100%" role="img" aria-label="bar chart">`;
      items.forEach((it, i) => {
        const bw = (o.w - lw - 70) * it.value / max, yy = i * rh + 2;
        s += `<text x="${lw - 8}" y="${yy + 16}" text-anchor="end">${esc(it.label)}</text><rect x="${lw}" y="${yy + 3}" width="${Math.max(2, bw)}" height="${rh - 9}" rx="3" fill="${it.color || COC.palette[i % 8]}"/><text x="${lw + bw + 6}" y="${yy + 16}">${esc(o.fmt(it.value))}</text>`;
      });
      return raw(s + '</svg>');
    },
    donut(items, o) {
      o = Object.assign({ size: 150, center: '' }, o || {});
      const tot = items.reduce((a, b) => a + b.value, 0) || 1, r = 52, c = 2 * Math.PI * r; let off = 0;
      let s = `<svg viewBox="0 0 150 150" width="${o.size}" height="${o.size}" role="img" aria-label="donut chart"><g transform="rotate(-90 75 75)">`;
      items.forEach((it, i) => { const len = c * it.value / tot; s += `<circle cx="75" cy="75" r="${r}" fill="none" stroke="${it.color || COC.palette[i % 8]}" stroke-width="20" stroke-dasharray="${len} ${c - len}" stroke-dashoffset="${-off}"><title>${esc(it.label)}: ${it.value}</title></circle>`; off += len; });
      s += `</g><text x="75" y="80" text-anchor="middle" style="fill:var(--text);font-size:18px;font-weight:600">${esc(o.center)}</text></svg>`;
      return raw(`<div class="row" style="gap:16px">${s}<div class="legend" style="flex-direction:column;gap:4px">${items.map((it, i) => `<span><i style="background:${it.color || COC.palette[i % 8]}"></i>${esc(it.label)} · ${it.value}</span>`).join('')}</div></div>`);
    },
    spark(data, color) {
      const w = 90, hh = 24, mn = Math.min(...data), mx = Math.max(...data), p = data.map((v, i) => `${(i / (data.length - 1) * w).toFixed(1)},${(hh - 2 - (v - mn) / (mx - mn || 1) * (hh - 4)).toFixed(1)}`).join(' ');
      return raw(`<svg width="${w}" height="${hh}" aria-hidden="true"><polyline fill="none" stroke="${color || 'var(--acc)'}" stroke-width="1.6" points="${p}"/></svg>`);
    },
  };

  /* ---------- download helper ---------- */
  COC.download = (name, text, type) => {
    const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([text], { type: type || 'text/plain' })); a.download = name; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 500);
  };
  COC.csv = (rows) => rows.map(r => r.map(c => '"' + String(c).replace(/"/g, '""') + '"').join(',')).join('\n');

  /* ---------- render / router ---------- */
  COC.route = () => (location.hash.replace(/^#\/?/, '') || 'map');
  COC.access = m => !m.roles || m.roles.includes(COC.state.role);
  COC.refresh = () => {
    const view = document.getElementById('view'), ae = document.activeElement;
    const keep = ae && ae.id && view.contains(ae) ? { id: ae.id, s: ae.selectionStart, e: ae.selectionEnd } : null;
    const top = view.scrollTop;
    const id = COC.route(), m = COC.modules.find(x => x.id === id) || COC.modules[0];
    document.title = m.name + ' · CloudOps Console (dummy)';
    document.documentElement.setAttribute('data-theme', COC.state.theme);
    document.body.classList.toggle('ro', !COC.can());
    COC.renderChrome(m);
    view.innerHTML = COC.access(m) ? m.render().s : h`<div class="card empty"><h2>🚫 Access denied</h2>Role <b>${COC.state.role}</b> cannot open <b>${m.name}</b>. Switch role in the header to explore.</div>`.s;
    view.scrollTop = top;
    if (keep) { const e = document.getElementById(keep.id); if (e) { e.focus(); try { e.setSelectionRange(keep.s, keep.e); } catch (_) { } } }
  };
  COC.renderChrome = m => {
    const phases = [[1, 'Phase 1 · Foundation'], [2, 'Phase 2 · Multi-cloud & Risk'], [3, 'Phase 3 · Automation & Governance'], [4, 'Phase 4 · Intelligence & Resilience']];
    document.getElementById('side').innerHTML = h`<div class="brand"><div class="logo">C</div><div>CloudOps Console<small>COC · dummy prototype</small></div></div>
      <nav class="nav"><a href="#/map" class="${m.id === 'map' ? 'on' : ''}"><span class="ic">🗺️</span>Feature Map</a>
      ${phases.map(([p, l]) => h`<div class="nav-h">${l}</div>${COC.modules.filter(x => x.phase === p).map(x => h`<a href="#/${x.id}" class="${x.id === m.id ? 'on' : ''}" ${COC.access(x) ? '' : raw('style="opacity:.4"')}><span class="ic">${x.icon}</span>${x.name}${x.isNew ? h`<span class="new">NEW</span>` : ''}</a>`)}`)}</nav>`.s;
    const open = COC.data.alerts ? COC.data.alerts.filter(a => a.state === 'firing').length : 0;
    document.getElementById('top').innerHTML = h`<b>${m.icon} ${m.name}</b><span class="sp"></span>
      <label class="mut">Tenant ${COC.ui.select('hdr-tenant', TENANTS, COC.state.tenant, 'hdr')}</label>
      <label class="mut">Role ${COC.ui.select('hdr-role', ROLES, COC.state.role, 'hdr')}</label>
      <a class="btn" href="#/alerting" title="Firing alerts">🔔 ${open}</a>
      <button class="btn" data-act="theme" aria-label="Toggle theme">${COC.state.theme === 'dark' ? '☀️' : '🌙'}</button>`.s;
  };
  COC.actions.hdr = (v, el) => { COC.state[el.id === 'hdr-tenant' ? 'tenant' : 'role'] = v; COC.refresh(); };
  COC.actions.theme = () => { COC.state.theme = COC.state.theme === 'dark' ? 'light' : 'dark'; COC.refresh(); };
  // per-module tab state: data-act="tab" data-arg="moduleId:tab"
  COC.tabs = {};
  COC.actions.tab = a => { const [m, t] = a.split(':'); COC.tabs[m] = t; COC.refresh(); };

  /* ---------- delegated events ---------- */
  function dispatch(name, arg, el, ev) {
    if (el.hasAttribute('data-w') && !COC.can()) { COC.toast('Read-only: role "' + COC.state.role + '" cannot change things.', 'warn'); if (el.type === 'checkbox') COC.refresh(); return; }
    const fn = COC.actions[name]; if (!fn) { console.warn('no action', name); return; }
    fn(arg, el, ev);
  }
  document.addEventListener('click', ev => {
    const el = ev.target.closest('[data-act]'); if (!el || el.disabled) return;
    dispatch(el.dataset.act, el.dataset.arg, el, ev);
  });
  document.addEventListener('change', ev => { const el = ev.target.closest('[data-chg]'); if (!el) return; dispatch(el.dataset.chg, el.type === 'checkbox' ? (el.dataset.arg + '|' + el.checked) : el.value, el, ev); });
  document.addEventListener('input', ev => { const el = ev.target.closest('[data-inp]'); if (el) dispatch(el.dataset.inp, el.value, el, ev); });
  window.addEventListener('hashchange', () => { COC.closeModal(); COC.refresh(); document.getElementById('view').scrollTop = 0; });
  document.addEventListener('keydown', ev => { if (ev.key === 'Escape') COC.closeModal(); });
  document.getElementById('overlay').addEventListener('click', ev => { if (ev.target.id === 'overlay') COC.closeModal(); });
})();
