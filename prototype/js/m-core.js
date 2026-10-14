/* Feature map, Dashboard, CMDB, Alerting, Cloud Connectors, OpenShift */
(function () {
  const { h, raw, ui, chart, data: D } = COC;
  const ALL = ['Platform Admin', 'Cloud Engineer', 'Ops/SRE', 'Client Viewer', 'Auditor'];
  const STAFF = ['Platform Admin', 'Cloud Engineer', 'Ops/SRE'];
  COC.roleSets = { ALL, STAFF };

  /* ================= FEATURE MAP ================= */
  COC.register({ id: 'map', name: 'Feature Map', icon: '🗺️', phase: 0, render() {
    const mods = COC.modules.filter(m => m.phase > 0);
    const ph = { 1: 'Foundation', 2: 'Multi-cloud & Risk', 3: 'Automation & Governance', 4: 'Intelligence & Resilience' };
    return h`<div class="ph"><div class="grow"><h1>CloudOps Console <span class="badge b-info">dummy</span></h1>
      <p class="sub">Click any module below – all ${mods.length} are wired up with mock data and working interactions. Use the header to switch <b>tenant</b> and <b>role</b> (RBAC changes what you can see and do).</p></div></div>
      <div class="grid g4">${[1, 2, 3, 4].map(p => ui.kpi('Phase ' + p, mods.filter(m => m.phase === p).length + ' modules', ph[p]))}</div>
      <div class="grid g21"><div class="card"><h2>Feature tree</h2><div class="tree">CloudOps Console<br>${mods.map((m, i) => h`${i === mods.length - 1 ? '└── ' : '├── '}<a href="#/${m.id}">${m.icon} ${m.name}</a> <span class="mut">[Phase ${m.phase}]</span>${m.isNew ? h` <span class="badge b-info">NEW</span>` : ''}<br>`)}</div></div>
      <div class="card"><h2>Try this walkthrough</h2><ol style="padding-left:18px;margin:0;line-height:1.9">
        <li><a href="#/connectors">Connectors</a> → Sync now / add one</li><li><a href="#/cmdb">CMDB</a> → run discovery, open an asset</li>
        <li><a href="#/alerting">Alerting</a> → build a rule, ack an alert</li><li><a href="#/iac">IaC Generator</a> → generate Terraform; watch the policy gate fail then pass</li>
        <li><a href="#/security">Security</a> → run a scan</li><li><a href="#/finops">FinOps</a> → apply rightsizing</li>
        <li><a href="#/aiops">AIOps</a> → execute a runbook</li><li><a href="#/incidents">Incident &amp; Change</a> → approve a change, advance an incident</li>
        <li><a href="#/pipelines">Pipelines</a> → roll back a deployment</li><li><a href="#/compliance">Compliance</a> → see the audit trail of everything you just did</li>
        <li>Switch role to <b>Client Viewer</b> → write actions lock, modules hide</li></ol></div></div>`;
  } });

  /* ================= DASHBOARD ================= */
  const DS = { cloud: 'All', region: 'All', env: 'All' };
  COC.actions['dash.f'] = (v, el) => { DS[el.dataset.arg] = v; COC.refresh(); };
  COC.register({ id: 'dashboard', name: 'Multi-Cloud Dashboard', icon: '🖥️', phase: 1, roles: ALL, render() {
    let rs = COC.byTenant(D.resources);
    const regions = [...new Set(rs.map(x => x.region))].sort();
    if (DS.cloud !== 'All') rs = rs.filter(x => x.cloud === DS.cloud);
    if (DS.region !== 'All') rs = rs.filter(x => x.region === DS.region);
    if (DS.env !== 'All') rs = rs.filter(x => x.env === DS.env);
    const avg = k => rs.length ? Math.round(rs.reduce((a, b) => a + b[k], 0) / rs.length) : 0;
    const spend = rs.reduce((a, b) => a + b.cost, 0), firing = COC.byTenant(D.alerts).filter(a => a.state === 'firing').length;
    const comp = Math.round(D.frameworks.reduce((a, b) => a + b.score, 0) / D.frameworks.length), openInc = COC.byTenant(D.incidents).filter(i => i.stage < 2).length;
    const byCloud = D.clouds.map(c => ({ label: c, value: rs.filter(x => x.cloud === c).length, color: COC.cloudColor[c] }));
    const cpuS = D.clouds.map(c => { const l = rs.filter(x => x.cloud === c); return { name: c, color: COC.cloudColor[c], data: Array.from({ length: 24 }, (_, i) => l.length ? Math.round(l.reduce((a, b) => a + b.cpuSeries[i], 0) / l.length) : 0) }; });
    const costBy = D.clouds.map(c => ({ label: c, value: rs.filter(x => x.cloud === c).reduce((a, b) => a + b.cost, 0), color: COC.cloudColor[c] }));
    return h`<div class="ph"><div class="grow"><h1>Multi-Cloud Dashboard</h1><p class="sub">Unified inventory, utilization and cost across AWS · Azure · GCP · OpenShift · IBM Cloud.</p></div>
      <div class="row"><label class="mut">Cloud ${ui.select('df-cloud', ['All', ...D.clouds], DS.cloud, 'dash.f', 'cloud')}</label>
      <label class="mut">Region ${ui.select('df-region', ['All', ...regions], DS.region, 'dash.f', 'region')}</label>
      <label class="mut">Env ${ui.select('df-env', ['All', ...D.envs], DS.env, 'dash.f', 'env')}</label></div></div>
      <div class="grid g6">${ui.kpi('Resources', rs.length)}${ui.kpi('Avg CPU', avg('cpu') + '%', avg('cpu') > 60 ? 'Running warm' : 'Healthy', avg('cpu') > 60 ? 'warn' : 'good')}${ui.kpi('Monthly spend', ui.fmt$(spend), '+4.2% vs last month', 'up')}${ui.kpi('Firing alerts', firing, '', firing > 5 ? 'bad' : '')}${ui.kpi('Compliance', comp + '%', 'avg of 5 frameworks')}${ui.kpi('Open incidents', openInc)}</div>
      <div class="grid g21"><div class="card"><h2>CPU utilization – last 24h, by cloud</h2>${chart.line(cpuS, { labels: Array.from({ length: 24 }, (_, i) => i + 'h'), fmt: v => v + '%', title: 'CPU by cloud', min: 0, max: 100 })}</div>
      <div class="card"><h2>Inventory by cloud</h2>${chart.donut(byCloud, { center: rs.length })}<h2 style="margin-top:14px">Monthly cost by cloud</h2>${chart.bars(costBy, { fmt: ui.fmt$ })}</div></div>
      <div class="grid g2"><div class="card flat"><div style="padding:14px 16px 0"><h2>Hottest resources</h2></div>${ui.table([{ h: 'Resource', f: r => r.name }, { h: 'Cloud', f: r => h`${ui.dot(COC.cloudColor[r.cloud])}${r.cloud}` }, { h: 'CPU', f: r => h`<div style="width:90px">${ui.bar(r.cpu)}</div>` }, { h: '%', num: 1, f: r => r.cpu }], [...rs].sort((a, b) => b.cpu - a.cpu).slice(0, 7))}</div>
      <div class="card flat"><div style="padding:14px 16px 0"><h2>Recent activity</h2></div>${ui.table([{ h: 'When', f: a => a.t.toLocaleTimeString() }, { h: 'Who', f: a => a.role }, { h: 'Action', f: a => a.action + (a.target ? ' · ' + a.target : '') }], COC.auditLog.slice(0, 7), { empty: 'Nothing yet – do something in another module and it shows up here and in the Audit Trail.' })}</div></div>`;
  } });

  /* ================= CMDB ================= */
  const CS = { q: '', cloud: 'All', env: 'All', discovering: false };
  COC.actions['cmdb.q'] = v => { CS.q = v; COC.refresh(); };
  COC.actions['cmdb.f'] = (v, el) => { CS[el.dataset.arg] = v; COC.refresh(); };
  COC.actions['cmdb.open'] = id => {
    const x = D.resources.find(r => r.id === id); if (!x) return;
    const cluster = x.type.match(/EKS|AKS|GKE|IKS|Cluster/) ? x.name : 'cluster-' + x.region, app = x.team + '-app';
    const rel = [['Cloud account', x.cloud + ' / ' + x.tenant], ['Region', x.region], ['Cluster', cluster], ['Namespace', x.env + '-' + x.team], ['App', app], ['Resource', x.name]];
    COC.modal({ title: x.name, wide: true, body: h`<div class="grid g2" style="margin:0"><div><h3>Attributes</h3><dl class="kv"><dt>ID</dt><dd>${x.id}</dd><dt>Type</dt><dd>${x.cloud} · ${x.type}</dd><dt>Env / SLA</dt><dd>${x.env} · ${x.sla}</dd><dt>Tenant</dt><dd>${x.tenant}</dd><dt>Owner / team</dt><dd>${x.owner} · ${x.team}</dd><dt>State</dt><dd>${x.state}</dd><dt>Tags</dt><dd>${Object.keys(x.tags).length ? Object.entries(x.tags).map(([k, v]) => h`<span class="badge">${k}=${v}</span> `) : ui.badge('untagged', 'bad')}</dd></dl>
        <h3 style="margin-top:14px">Relationship map</h3><div class="tree">${rel.map((p, i) => h`${'  '.repeat(i)}${i ? '└─ ' : ''}<b>${p[0]}</b>: ${p[1]}<br>`)}</div></div>
        <div><h3>CPU – last 24h</h3>${chart.line([{ name: 'cpu', data: x.cpuSeries }], { h: 150, fmt: v => v + '%', min: 0, max: 100 })}<h3 style="margin-top:12px">Config change history</h3>${ui.table([{ h: 'Date', f: e => e.t }, { h: 'By', f: e => e.who }, { h: 'Change', f: e => e.what }], x.history)}</div></div>`, actions: [{ label: 'Close' }] });
  };
  COC.actions['cmdb.discover'] = () => {
    if (CS.discovering) return; CS.discovering = true; COC.refresh(); COC.toast('Discovery started across 5 connectors…');
    setTimeout(() => {
      const n = 3 + Math.floor(Math.random() * 4); const base = D.resources.length;
      for (let i = 0; i < n; i++) { const c = D.clouds[i % 5]; D.resources.unshift({ id: 'ci-' + (2000 + base + i), name: 'discovered-' + c.toLowerCase().replace(/\s/g, '') + '-' + (base + i), cloud: c, type: D.cloudMeta[c].types[0], region: D.cloudMeta[c].regions[0], env: 'dev', tenant: COC.TENANTS[1 + i % 4], team: 'platform', owner: 'discovery', sla: 'Bronze', cpu: 12, mem: 20, disk: 30, net: 5, cost: 120, state: 'running', tags: {}, vulns: 0, public: false, backup: false, backupAgeH: 999, created: '2026-10-14', cpuSeries: D.series(24, 15, 6), history: [{ t: '2026-10-14', who: 'discovery', what: 'Asset auto-discovered' }] }); }
      CS.discovering = false; COC.audit('CMDB discovery run', '+' + n + ' assets'); COC.toast(n + ' new assets discovered (untagged – see Compliance)', 'ok'); COC.refresh();
    }, 1600);
  };
  COC.actions['cmdb.add'] = () => COC.modal({ title: 'Register asset manually', body: h`<label class="f">Name<input id="n-name" placeholder="e.g. legacy-mainframe-gw"></label><label class="f">Cloud${ui.select('n-cloud', D.clouds, 'AWS', 'noop')}</label><label class="f">Environment${ui.select('n-env', D.envs, 'prod', 'noop')}</label><label class="f">Owner<input id="n-owner" value="jayant"></label>`, actions: [{ label: 'Cancel' }, { label: 'Register', primary: true, fn: () => {
    const name = COC.v('n-name').trim(); if (!name) { COC.toast('Name required', 'bad'); return false; }
    const c = COC.v('n-cloud'); D.resources.unshift({ id: 'ci-' + (3000 + D.resources.length), name, cloud: c, type: 'Manual', region: D.cloudMeta[c].regions[0], env: COC.v('n-env'), tenant: COC.state.tenant === COC.TENANTS[0] ? 'IBM Internal' : COC.state.tenant, team: 'platform', owner: COC.v('n-owner'), sla: 'Bronze', cpu: 0, mem: 0, disk: 0, net: 0, cost: 0, state: 'running', tags: {}, vulns: 0, public: false, backup: false, backupAgeH: 999, created: '2026-10-14', cpuSeries: Array(24).fill(0), history: [{ t: '2026-10-14', who: COC.state.role, what: 'Manually registered' }] });
    COC.audit('CMDB asset registered', name); COC.toast('Registered ' + name, 'ok'); COC.refresh();
  } }] });
  COC.actions.noop = () => { };
  COC.register({ id: 'cmdb', name: 'CMDB', icon: '📦', phase: 1, roles: ALL, render() {
    let rs = COC.byTenant(D.resources);
    if (CS.cloud !== 'All') rs = rs.filter(x => x.cloud === CS.cloud); if (CS.env !== 'All') rs = rs.filter(x => x.env === CS.env);
    const q = CS.q.toLowerCase(); if (q) rs = rs.filter(x => (x.name + x.owner + x.team + x.type + x.region).toLowerCase().includes(q));
    const untagged = rs.filter(x => !Object.keys(x.tags).length).length;
    return h`<div class="ph"><div class="grow"><h1>CMDB</h1><p class="sub">Auto-discovered configuration items with relationships, tags, owners, SLA tier and full change history.</p></div>
      <div class="row"><button class="btn p" data-act="cmdb.discover" data-w ${CS.discovering ? raw('disabled') : ''}>${CS.discovering ? '⏳ Discovering…' : '🔍 Run discovery'}</button><button class="btn" data-act="cmdb.add" data-w>＋ Register asset</button></div></div>
      <div class="grid g4">${ui.kpi('Configuration items', rs.length)}${ui.kpi('Untagged', untagged, untagged ? 'violates require-tags policy' : 'all tagged', untagged ? 'bad' : 'good')}${ui.kpi('Public-facing', rs.filter(x => x.public).length)}${ui.kpi('Stopped', rs.filter(x => x.state !== 'running').length)}</div>
      <div class="card flat"><div class="row" style="padding:12px 14px"><input id="cmdb-q" data-inp="cmdb.q" placeholder="Search name, owner, team, type…" value="${CS.q}" style="width:280px"><span class="mut">Cloud</span>${ui.select('cmdb-cloud', ['All', ...D.clouds], CS.cloud, 'cmdb.f', 'cloud')}<span class="mut">Env</span>${ui.select('cmdb-env', ['All', ...D.envs], CS.env, 'cmdb.f', 'env')}<span class="mut">${rs.length} shown</span></div>
      ${ui.table([{ h: 'Name', f: r => r.name }, { h: 'Cloud', f: r => h`${ui.dot(COC.cloudColor[r.cloud])}${r.cloud}` }, { h: 'Type', f: r => r.type }, { h: 'Region', f: r => r.region }, { h: 'Env', f: r => ui.badge(r.env, r.env === 'prod' ? 'warn' : '') }, { h: 'Tenant', f: r => r.tenant }, { h: 'Owner', f: r => r.owner }, { h: 'SLA', f: r => r.sla }, { h: 'CPU', num: 1, f: r => r.cpu + '%' }, { h: 'Tags', f: r => Object.keys(r.tags).length ? '✓' : ui.badge('none', 'bad') }], rs.slice(0, 40), { click: 'cmdb.open', key: r => r.id })}</div>${rs.length > 40 ? h`<p class="mut">Showing first 40 of ${rs.length}. (Pagination arrives with the real build.)</p>` : ''}`;
  } });

  /* ================= ALERTING ================= */
  COC.actions['al.ack'] = id => { const a = D.alerts.find(x => x.id === id); a.state = 'ack'; COC.audit('Alert acknowledged', id); COC.toast(id + ' acknowledged'); COC.refresh(); };
  COC.actions['al.sil'] = id => { const a = D.alerts.find(x => x.id === id); a.state = 'silenced'; COC.audit('Alert silenced (2h)', id); COC.toast(id + ' silenced for 2h'); COC.refresh(); };
  COC.actions['al.esc'] = id => { const a = D.alerts.find(x => x.id === id); a.sev = 'critical'; COC.audit('Alert escalated to PagerDuty', id); COC.toast(id + ' escalated → PagerDuty on-call', 'warn'); COC.refresh(); };
  COC.actions['al.resolve'] = id => { D.alerts = D.alerts.filter(x => x.id !== id); COC.audit('Alert resolved', id); COC.refresh(); };
  COC.actions['al.rule'] = a => { const [id, on] = a.split('|'); D.rules.find(r => r.id === id).enabled = on === 'true'; COC.audit('Rule ' + (on === 'true' ? 'enabled' : 'disabled'), id); COC.refresh(); };
  COC.actions['al.chan'] = a => { const [n, on] = a.split('|'); D.channels.find(c => c.name === n).on = on === 'true'; COC.audit('Channel toggled', n); COC.refresh(); };
  COC.actions['al.test'] = n => COC.toast('✔ Test notification sent via ' + n, 'ok');
  COC.actions['al.new'] = () => COC.modal({ title: 'Alert rule builder', body: h`<label class="f">Rule name<input id="r-name" placeholder="e.g. Redis memory > 90%"></label><div class="grid g3" style="margin:0"><label class="f">Type${ui.select('r-kind', ['threshold', 'anomaly', 'comparison'], 'threshold', 'noop')}</label><label class="f">Metric${ui.select('r-metric', ['cpu.used_pct', 'mem.used_pct', 'disk.used_pct', 'k8s.pod.restarts', 'cost.daily_delta', 'net.egress_mb'], 'cpu.used_pct', 'noop')}</label><label class="f">Operator${ui.select('r-op', ['>', '<', '>=', '==', 'deviates'], '>', 'noop')}</label></div><div class="grid g3" style="margin:0"><label class="f">Threshold<input id="r-thr" type="number" value="85"></label><label class="f">For${ui.select('r-dur', ['1m', '5m', '15m', '1h'], '5m', 'noop')}</label><label class="f">Severity${ui.select('r-sev', ['critical', 'high', 'medium', 'low'], 'high', 'noop')}</label></div><label class="f">Channels</label><div class="row">${D.channels.map(c => h`<label class="chip"><input type="checkbox" class="r-ch" value="${c.name}" ${c.name === 'Slack' ? raw('checked') : ''}> ${c.name}</label>`)}</div>`, actions: [{ label: 'Cancel' }, { label: 'Create rule', primary: true, fn: () => {
    const name = COC.v('r-name').trim(); if (!name) { COC.toast('Give the rule a name', 'bad'); return false; }
    const ch = [...document.querySelectorAll('.r-ch:checked')].map(e => e.value);
    D.rules.push({ id: 'r' + Date.now(), name, metric: COC.v('r-metric'), op: COC.v('r-op'), thr: +COC.v('r-thr'), dur: COC.v('r-dur'), sev: COC.v('r-sev'), channels: ch.length ? ch : ['Email'], enabled: true, kind: COC.v('r-kind') });
    COC.audit('Alert rule created', name); COC.toast('Rule created', 'ok'); COC.refresh();
  } }] });
  COC.register({ id: 'alerting', name: 'Alerting Engine', icon: '🔔', phase: 2, roles: ALL, render() {
    const t = COC.tabs.alerting || 'active', al = COC.byTenant(D.alerts);
    const body = t === 'active' ? h`<div class="card flat">${ui.table([{ h: 'ID', f: a => a.id }, { h: 'Severity', f: a => ui.sev(a.sev) }, { h: 'Alert', f: a => a.title }, { h: 'Resource', f: a => a.res }, { h: 'Cloud', f: a => a.cloud }, { h: 'Since', f: a => ui.ago(a.since) }, { h: 'State', f: a => ui.badge(a.state, a.state === 'firing' ? 'bad' : a.state === 'ack' ? 'warn' : 'mut') }, { h: '', f: a => h`<div class="row">${ui.btn('Ack', 'al.ack', a.id, { s: 1, w: 1 })}${ui.btn('Silence', 'al.sil', a.id, { s: 1, w: 1 })}${ui.btn('Escalate', 'al.esc', a.id, { s: 1, w: 1 })}${ui.btn('Resolve', 'al.resolve', a.id, { s: 1, w: 1 })}</div>` }], al, { empty: '🎉 No alerts for this tenant.' })}</div>`
      : t === 'rules' ? h`<div class="row" style="margin-bottom:10px"><button class="btn p" data-act="al.new" data-w>＋ New rule (builder)</button></div><div class="card flat">${ui.table([{ h: 'On', f: r => ui.sw(r.enabled, 'al.rule', r.id) }, { h: 'Rule', f: r => r.name }, { h: 'Type', f: r => ui.badge(r.kind, r.kind === 'anomaly' ? 'purple' : '') }, { h: 'Condition', f: r => h`<code>${r.metric} ${r.op} ${r.thr}</code> for ${r.dur}` }, { h: 'Severity', f: r => ui.sev(r.sev) }, { h: 'Channels', f: r => r.channels.join(', ') }], D.rules)}</div>`
        : h`<div class="grid g3">${D.channels.map(c => h`<div class="card"><h2>${c.name} ${ui.sw(c.on, 'al.chan', c.name)}</h2><p class="mut">${c.target}</p>${ui.btn('Send test', 'al.test', c.name, { s: 1 })}</div>`)}</div><div class="card"><h2>Escalation policy</h2><div class="stepper"><div class="st done">0m · Slack</div><div class="st done">5m · Email on-call</div><div class="st cur">15m · PagerDuty</div><div class="st">30m · Manager (Teams)</div></div></div>`;
    return h`<div class="ph"><div class="grow"><h1>Alerting Engine</h1><p class="sub">Threshold, anomaly and comparison rules → Email, Slack, PagerDuty, MS Teams. Silence, acknowledge and escalate.</p></div></div>
      <div class="grid g4">${ui.kpi('Firing', al.filter(a => a.state === 'firing').length, '', 'bad')}${ui.kpi('Acknowledged', al.filter(a => a.state === 'ack').length)}${ui.kpi('Silenced', al.filter(a => a.state === 'silenced').length)}${ui.kpi('Rules enabled', D.rules.filter(r => r.enabled).length + '/' + D.rules.length)}</div>
      ${ui.tabs('alerting', [['active', 'Active alerts'], ['rules', 'Rules'], ['channels', 'Channels & escalation']], t)}${body}`;
  } });

  /* ================= CONNECTORS ================= */
  COC.actions['cn.test'] = id => { const c = D.connectors.find(x => x.id === id); COC.toast('Testing ' + c.cloud + '…'); setTimeout(() => { c.status = 'healthy'; COC.audit('Connector tested', c.name); COC.toast('✔ ' + c.cloud + ' credentials valid (read-only role)', 'ok'); COC.refresh(); }, 700); };
  COC.actions['cn.sync'] = id => { const c = D.connectors.find(x => x.id === id); c.status = 'syncing'; COC.refresh(); setTimeout(() => { c.status = 'healthy'; c.last = 0; c.items += 3; COC.audit('Connector synced', c.name); COC.toast('Synced ' + c.cloud + ' (+3 items)', 'ok'); COC.refresh(); }, 1100); };
  COC.actions['cn.add'] = () => COC.modal({ title: 'Add cloud connector', body: h`<label class="f">Cloud${ui.select('cn-cloud', D.clouds, 'AWS', 'noop')}</label><label class="f">Display name<input id="cn-name" placeholder="e.g. aws-dr-account"></label><label class="f">Credential reference (stored in Vault)<input id="cn-ref" value="vault://secret/coc/new-connector"></label><p class="mut">The real build stores only a Vault path – never raw keys.</p>`, actions: [{ label: 'Cancel' }, { label: 'Connect', primary: true, fn: () => {
    const name = COC.v('cn-name').trim(); if (!name) { COC.toast('Name required', 'bad'); return false; }
    const cl = COC.v('cn-cloud'); D.connectors.push({ id: 'c' + Date.now(), cloud: cl, name, sdk: 'adapter', scope: D.cloudMeta[cl].types.join(', '), status: 'healthy', last: 0, items: 0, phase: 'P2' }); COC.audit('Connector added', name); COC.toast('Connector added', 'ok'); COC.refresh();
  } }] });
  COC.register({ id: 'connectors', name: 'Cloud Connectors', icon: '☁️', phase: 1, roles: ['Platform Admin', 'Cloud Engineer', 'Auditor'], render() {
    return h`<div class="ph"><div class="grow"><h1>Cloud Connectors</h1><p class="sub">Pluggable adapters behind one interface; every cloud returns the same normalized resource schema.</p></div><button class="btn p" data-act="cn.add" data-w>＋ Add connector</button></div>
      <div class="grid g3">${D.connectors.map(c => h`<div class="card"><h2>${ui.dot(COC.cloudColor[c.cloud])}${c.cloud} ${ui.badge(c.phase)}</h2><div><b>${c.name}</b></div><dl class="kv" style="margin:10px 0"><dt>SDK</dt><dd>${c.sdk}</dd><dt>Scope</dt><dd>${c.scope}</dd><dt>Items</dt><dd>${c.items}</dd><dt>Last sync</dt><dd>${c.last ? ui.ago(c.last) : 'just now'}</dd><dt>Status</dt><dd>${ui.badge(c.status, c.status === 'healthy' ? 'ok' : c.status === 'syncing' ? 'info' : 'warn')}</dd></dl><div class="row">${ui.btn('Test', 'cn.test', c.id, { s: 1, w: 1 })}${ui.btn('Sync now', 'cn.sync', c.id, { s: 1, p: 1, w: 1 })}</div></div>`)}</div>
      <div class="card"><h2>Normalized schema (all adapters)</h2>${ui.pre('{ id, cloud, type, name, region, env, tenant_id, tags{}, owner, state,\n  metrics{cpu,mem,disk,net}, cost_month, relationships[], raw{} }')}</div>`;
  } });

  /* ================= OPENSHIFT ================= */
  COC.actions['ocp.op'] = a => { const [id, on] = a.split('|'); const o = D.operators.find(x => x.name === id); o.installed = on === 'true'; COC.audit('Operator ' + (o.installed ? 'installed' : 'removed'), o.name); COC.toast(o.name + (o.installed ? ' installed' : ' removed'), 'ok'); COC.refresh(); };
  COC.actions['ocp.quota'] = n => { const ns = D.namespaces.find(x => x.name === n); COC.modal({ title: 'Edit quota – ' + n, body: h`<label class="f">CPU quota (cores)<input id="q-cpu" type="number" value="${ns.cpuQ}"></label><label class="f">Memory quota (GiB)<input id="q-mem" type="number" value="${ns.memQ}"></label>`, actions: [{ label: 'Cancel' }, { label: 'Apply', primary: true, fn: () => { ns.cpuQ = +COC.v('q-cpu'); ns.memQ = +COC.v('q-mem'); COC.audit('Quota updated', n); COC.toast('Quota applied to ' + n, 'ok'); COC.refresh(); } }] }); };
  COC.actions['ocp.ns'] = () => COC.modal({ title: 'Create namespace', body: h`<label class="f">Name<input id="ns-n" placeholder="team-project"></label><label class="f">Cluster${ui.select('ns-c', D.clusters.map(c => c.name), 'ocp-prod-01', 'noop')}</label>`, actions: [{ label: 'Cancel' }, { label: 'Create', primary: true, fn: () => { const n = COC.v('ns-n').trim(); if (!n) { COC.toast('Name required', 'bad'); return false; } D.namespaces.push({ name: n, cpuReq: 0, cpuQ: 16, memReq: 0, memQ: 64, pods: 0, bad: 0, cluster: COC.v('ns-c') }); COC.audit('Namespace created', n); COC.refresh(); } }] });
  COC.register({ id: 'openshift', name: 'OpenShift Module', icon: '🔴', phase: 1, roles: STAFF.concat('Auditor'), render() {
    const t = COC.tabs.openshift || 'health';
    const pods = () => h`<div class="pods">${D.namespaces.flatMap(n => Array.from({ length: n.pods }, (_, i) => h`<i class="${i < n.bad ? (i % 2 ? 'w' : 'x') : ''}" title="${n.name}"></i>`))}</div>`;
    const body = t === 'health' ? h`<div class="grid g3">${D.clusters.map(c => h`<div class="card"><h2>${c.name}</h2><p class="mut">OCP ${c.ver} · ${c.nodes} nodes · ${c.dc}</p>CPU ${c.cpu}% ${ui.bar(c.cpu)}<div style="height:6px"></div>Memory ${c.mem}% ${ui.bar(c.mem)}</div>`)}</div><div class="card"><h2>Pod health at a glance</h2>${pods()}<div class="legend"><span><i style="background:var(--ok)"></i>Running</span><span><i style="background:var(--warn)"></i>Pending</span><span><i style="background:var(--bad)"></i>CrashLoop</span></div></div>`
      : t === 'ns' ? h`<div class="row" style="margin-bottom:10px"><button class="btn p" data-act="ocp.ns" data-w>＋ Namespace</button></div><div class="card flat">${ui.table([{ h: 'Namespace', f: n => n.name }, { h: 'Cluster', f: n => n.cluster }, { h: 'CPU quota', f: n => h`<div style="width:130px">${ui.bar(n.cpuReq / n.cpuQ * 100)}</div><small class="mut">${n.cpuReq}/${n.cpuQ} cores</small>` }, { h: 'Mem quota', f: n => h`<div style="width:130px">${ui.bar(n.memReq / n.memQ * 100)}</div><small class="mut">${n.memReq}/${n.memQ} GiB</small>` }, { h: 'Pods', num: 1, f: n => n.pods }, { h: 'Unhealthy', num: 1, f: n => n.bad ? ui.badge(n.bad, 'bad') : '0' }, { h: '', f: n => ui.btn('Edit quota', 'ocp.quota', n.name, { s: 1, w: 1 }) }], D.namespaces)}</div>`
        : t === 'ops' ? h`<div class="card flat">${ui.table([{ h: 'Operator', f: o => o.name }, { h: 'Category', f: o => ui.badge(o.cat) }, { h: 'Version', f: o => o.ver }, { h: 'Installed', f: o => ui.sw(o.installed, 'ocp.op', o.name) }], D.operators)}</div>`
          : t === 'rbac' ? h`<div class="card flat">${ui.table([{ h: 'Subject', f: r => r.subject }, { h: 'Kind', f: r => r.kind }, { h: 'Role', f: r => ui.badge(r.role, r.role === 'cluster-admin' ? 'bad' : '') }, { h: 'Scope', f: r => r.ns }], D.rbac)}</div>`
            : h`<div class="card flat">${ui.table([{ h: 'Host', f: r => r.host }, { h: 'Service', f: r => r.svc }, { h: 'Namespace', f: r => r.ns }, { h: 'TLS', f: r => ui.badge(r.tls, r.tls === 'none' ? 'bad' : 'ok') }], D.routes)}</div>`;
    return h`<div class="ph"><div class="grow"><h1>OpenShift Module</h1><p class="sub">HCC-parity: namespaces &amp; quotas, operator catalog, RBAC viewer, pod health, routes.</p></div></div>${ui.tabs('openshift', [['health', 'Cluster & pod health'], ['ns', 'Namespaces & quotas'], ['ops', 'Operator catalog'], ['rbac', 'RBAC viewer'], ['routes', 'Routes / ingress']], t)}${body}`;
  } });
})();
