/* Image & SBOM Governance, Pipeline & Deployment Tracking */
(function () {
  const { h, raw, ui, data: D } = COC, { STAFF, ALL } = COC.roleSets;

  /* ================= IMAGES & SBOM ================= */
  const NEXT = { dev: 'staging', staging: 'prod' }, IM = { sbom: 'payments-api' };
  COC.actions['im.promote'] = id => {
    const i = D.images.find(x => x.id === id), nxt = NEXT[i.env]; if (!nxt) return;
    const why = i.sev === 'critical' ? 'critical CVEs' : !i.signed ? 'image not signed' : nxt === 'prod' && i.sev === 'high' ? 'high CVEs not allowed in prod' : null;
    if (why) { COC.audit('Image promotion BLOCKED', i.name + ' → ' + nxt + ' (' + why + ')'); COC.toast('Blocked: ' + why, 'bad'); return; }
    i.env = nxt; COC.audit('Image promoted', i.name + ':' + i.tag + ' → ' + nxt); COC.toast(i.name + ' promoted to ' + nxt, 'ok'); COC.refresh();
  };
  COC.actions['im.sbom'] = v => { IM.sbom = v; COC.refresh(); };
  COC.actions['im.csv'] = () => { COC.download('sbom-' + IM.sbom + '.csv', COC.csv([['package', 'version', 'license', 'flag'], ...D.sbom.map(s => [s.pkg, s.ver, s.lic, s.flag])]), 'text/csv'); COC.audit('SBOM exported', IM.sbom); };
  COC.register({ id: 'images', name: 'Image & SBOM Governance', icon: '📦', phase: 3, roles: ALL, render() {
    const t = COC.tabs.images || 'inv';
    let body;
    if (t === 'inv') body = h`<div class="card flat">${ui.table([{ h: 'Image', f: i => i.name + ':' + i.tag }, { h: 'Registry', f: i => i.reg }, { h: 'Env', f: i => ui.badge(i.env, i.env === 'prod' ? 'warn' : '') }, { h: 'Runtime', f: i => i.rt }, { h: 'CVEs', num: 1, f: i => h`${ui.sev(i.sev)} ${i.cves}` }, { h: 'Signed', f: i => i.signed ? '✓' : ui.badge('no', 'bad') }], D.images)}</div>`;
    else if (t === 'promo') body = h`<div class="card"><h2>Promotion gates: dev → staging → prod</h2><p class="mut">Gate rules: signed image · no critical CVEs · no high CVEs in prod.</p></div><div class="card flat">${ui.table([{ h: 'Image', f: i => i.name + ':' + i.tag }, { h: 'Stage', f: i => h`<div class="stepper" style="min-width:230px">${['dev', 'staging', 'prod'].map((s, k) => h`<div class="st ${k < ['dev', 'staging', 'prod'].indexOf(i.env) ? 'done' : s === i.env ? 'cur' : ''}">${s}</div>`)}</div>` }, { h: 'Gate check', f: i => i.sev === 'critical' || !i.signed ? ui.badge('would fail', 'bad') : ui.badge('would pass', 'ok') }, { h: '', f: i => NEXT[i.env] ? ui.btn('Promote → ' + NEXT[i.env], 'im.promote', i.id, { s: 1, p: 1, w: 1 }) : ui.badge('in prod', 'mut') }], D.images)}</div>`;
    else if (t === 'sbom') body = h`<div class="row" style="margin-bottom:10px"><span class="mut">Image</span>${ui.select('im-s', D.images.map(i => i.name), IM.sbom, 'im.sbom')}<button class="btn" data-act="im.csv">⬇ Export SBOM (CSV)</button></div><div class="card flat">${ui.table([{ h: 'Component', f: s => s.pkg }, { h: 'Version', f: s => s.ver }, { h: 'License', f: s => s.lic }, { h: 'Flag', f: s => s.flag === 'ok' ? ui.badge('ok', 'ok') : s.flag === 'vuln' ? ui.badge('vulnerable', 'bad') : s.flag === 'copyleft' ? ui.badge('copyleft – legal review', 'warn') : ui.badge('review', 'info') }], D.sbom)}</div>`;
    else body = h`<div class="card flat">${ui.table([{ h: 'Runtime', f: e => e.rt }, { h: 'Lifecycle', f: e => ui.badge(e.eol, 'bad') }, { h: 'Affected', f: e => e.where }], D.eol)}</div>`;
    return h`<div class="ph"><div class="grow"><h1>Image &amp; SBOM Governance</h1><p class="sub">Registry inventory, promotion policies, SBOM &amp; license compliance, EOL runtime detection.</p></div></div>
      <div class="grid g4">${ui.kpi('Images running', D.images.length)}${ui.kpi('Unsigned', D.images.filter(i => !i.signed).length, '', 'bad')}${ui.kpi('EOL runtimes', D.eol.length, '', 'warn')}${ui.kpi('Copyleft licenses', D.sbom.filter(s => s.flag === 'copyleft').length)}</div>
      ${ui.tabs('images', [['inv', 'Registry inventory'], ['promo', 'Promotion gates'], ['sbom', 'SBOM & licenses'], ['eol', 'EOL runtimes']], t)}${body}`;
  } });

  /* ================= PIPELINES & DEPLOYMENTS ================= */
  COC.actions['pl.rerun'] = app => { const p = D.pipelines.find(x => x.app === app); p.status = 'running'; COC.refresh(); setTimeout(() => { p.status = 'success'; p.run++; COC.audit('Pipeline re-run', app); COC.toast(app + ' pipeline succeeded', 'ok'); COC.refresh(); }, 1400); };
  COC.actions['pl.cell'] = k => {
    const d = D.deploy[k], [app, cl] = k.split('|'); if (!d) return;
    COC.modal({ title: app + ' @ ' + cl, wide: true, body: h`<dl class="kv"><dt>Version</dt><dd><b>${d.ver}</b> (previous ${d.prev})</dd><dt>Namespace</dt><dd>${d.ns}</dd><dt>Deployed</dt><dd>${d.at} by ${d.by}</dd><dt>Health</dt><dd>${d.healthy ? ui.badge('healthy', 'ok') : ui.badge('degraded', 'bad')}</dd></dl><h3 style="margin-top:14px">Diff ${d.prev} → ${d.ver}</h3><div class="diff"><div class="r">- image: ${app}:${d.prev}</div><div class="a">+ image: ${app}:${d.ver}</div><div class="r">-   replicas: 2</div><div class="a">+   replicas: 3</div><div class="a">+   env: FEATURE_X=true</div><div>    resources: { cpu: 500m }</div></div>`,
      actions: [{ label: 'Close' }, { label: '↩ Roll back to ' + d.prev, danger: true, fn: () => { if (!COC.can()) { COC.toast('Read-only role', 'warn'); return false; } const old = d.ver; d.ver = d.prev; d.prev = old; d.at = '2026-10-14'; d.by = 'jayant'; d.healthy = true; D.deployHist.unshift({ app, cl, from: old, to: d.ver, at: new Date().toLocaleTimeString(), kind: 'rollback' }); COC.audit('Deployment rolled back', app + '@' + cl + ' ' + old + '→' + d.ver); COC.toast('Rolled back ' + app + ' on ' + cl + ' to ' + d.ver, 'ok'); COC.refresh(); } }] });
  };
  COC.register({ id: 'pipelines', name: 'Pipeline & Deployment Tracking', icon: '🔁', phase: 3, roles: ALL, render() {
    const t = COC.tabs.pipelines || 'pl';
    let body;
    if (t === 'pl') body = h`<div class="card flat">${ui.table([{ h: 'App', f: p => p.app }, { h: 'Engine', f: p => ui.badge(p.eng) }, { h: 'Last run', num: 1, f: p => '#' + p.run }, { h: 'Duration', num: 1, f: p => p.mins + ' min' }, { h: 'Status', f: p => ui.badge(p.status, p.status === 'success' ? 'ok' : p.status === 'failed' ? 'bad' : 'info') }, { h: '', f: p => p.status === 'failed' ? ui.btn('Re-run', 'pl.rerun', p.app, { s: 1, p: 1, w: 1 }) : '' }], D.pipelines)}</div>`;
    else if (t === 'dep') body = h`<div class="card flat"><div class="tw"><table class="tbl"><thead><tr><th>App \\ Cluster</th>${D.deployClusters.map(c => h`<th>${c}</th>`)}</tr></thead><tbody>${D.apps.map(a => h`<tr><td><b>${a}</b></td>${D.deployClusters.map(c => { const d = D.deploy[a + '|' + c]; return d ? h`<td><button class="btn s" data-act="pl.cell" data-arg="${a + '|' + c}">${d.healthy ? '🟢' : '🔴'} v${d.ver}</button></td>` : h`<td class="mut">—</td>`; })}</tr>`)}</tbody></table></div></div><p class="mut">Click any version to see the diff and roll back with one click.</p>`;
    else body = h`<div class="card flat">${ui.table([{ h: 'When', f: x => x.at }, { h: 'App', f: x => x.app }, { h: 'Cluster', f: x => x.cl }, { h: 'Change', f: x => x.from + ' → ' + x.to }, { h: 'Kind', f: x => ui.badge(x.kind, 'warn') }], D.deployHist, { empty: 'No rollbacks yet. Open Deployments, click a version, and roll back.' })}</div>`;
    return h`<div class="ph"><div class="grow"><h1>Pipeline &amp; Deployment Tracking</h1><p class="sub">CI/CD status across Tekton · Jenkins · GitHub Actions, what runs where, history/diff, one-click rollback.</p></div></div>
      <div class="grid g4">${ui.kpi('Pipelines', D.pipelines.length)}${ui.kpi('Failing', D.pipelines.filter(p => p.status === 'failed').length, '', 'bad')}${ui.kpi('Deployments tracked', Object.keys(D.deploy).length)}${ui.kpi('Rollbacks (session)', D.deployHist.length)}</div>
      ${ui.tabs('pipelines', [['pl', 'Pipelines'], ['dep', 'Deployments matrix'], ['hist', 'Rollback history']], t)}${body}`;
  } });
})();
