/* Security, Compliance & Governance, IAM Governance, Certificate & Secret Mgmt */
(function () {
  const { h, raw, ui, chart, data: D } = COC, { STAFF, ALL } = COC.roleSets;
  const SEC = ['Platform Admin', 'Cloud Engineer', 'Ops/SRE', 'Auditor'];

  /* ================= SECURITY ================= */
  const SS = { running: null, ran: {}, sev: 'All' };
  const TOOLS = { sast: 'Checkov / tfsec', image: 'Trivy / Grype', secrets: 'GitLeaks / truffleHog', dast: 'ZAP (DAST)', cis: 'kube-bench' };
  COC.actions['sec.scan'] = k => { SS.running = k; COC.refresh(); setTimeout(() => { SS.running = null; SS.ran[k] = true; COC.audit('Security scan run: ' + TOOLS[k]); COC.toast(TOOLS[k] + ' finished', 'ok'); COC.refresh(); }, 1200); };
  COC.actions['sec.sev'] = v => { SS.sev = v; COC.refresh(); };
  COC.actions['sec.ticket'] = id => { COC.audit('Jira ticket created for finding', id); COC.toast('Jira SEC-' + (100 + Math.floor(Math.random() * 800)) + ' created for ' + id, 'ok'); };
  COC.actions['sec.vstatus'] = id => { const v = D.vulns.find(x => x.cve === id); v.status = v.status === 'open' ? 'in-progress' : 'fixed'; COC.audit('CVE status → ' + v.status, id); COC.refresh(); };
  const scanBtn = k => h`<div class="row" style="margin-bottom:10px"><button class="btn p" data-act="sec.scan" data-arg="${k}" data-w ${SS.running ? raw('disabled') : ''}>${SS.running === k ? '⏳ Scanning…' : '▶ Run ' + TOOLS[k]}</button>${SS.ran[k] ? ui.badge('scanned just now', 'ok') : ui.badge('last scan: 2d ago', 'mut')}</div>`;
  COC.register({ id: 'security', name: 'Security & Vulnerability', icon: '🔐', phase: 2, roles: SEC, render() {
    const t = COC.tabs.security || 'cve', vs = COC.byTenant(D.vulns).filter(v => SS.sev === 'All' || v.sev === SS.sev);
    const cnt = s => COC.byTenant(D.vulns).filter(v => v.sev === s && v.status !== 'fixed').length;
    let body;
    if (t === 'cve') body = h`<div class="grid g4">${['critical', 'high', 'medium', 'low'].map(s => ui.kpi(s.toUpperCase(), cnt(s), 'open CVEs', s === 'critical' ? 'bad' : ''))}</div><div class="row" style="margin-bottom:8px"><span class="mut">Severity</span>${ui.select('sec-sev', ['All', 'critical', 'high', 'medium', 'low'], SS.sev, 'sec.sev')}</div><div class="card flat">${ui.table([{ h: 'CVE', f: v => v.cve }, { h: 'Sev', f: v => ui.sev(v.sev) }, { h: 'CVSS', num: 1, f: v => v.cvss }, { h: 'Package', f: v => v.pkg }, { h: 'Asset', f: v => v.asset }, { h: 'Cloud', f: v => v.cloud }, { h: 'Age', num: 1, f: v => v.age + 'd' }, { h: 'Fix', f: v => v.fixed }, { h: 'Status', f: v => ui.badge(v.status, v.status === 'fixed' ? 'ok' : v.status === 'open' ? 'bad' : 'info') }, { h: '', f: v => v.status === 'fixed' ? '' : ui.btn(v.status === 'open' ? 'Start fix' : 'Mark fixed', 'sec.vstatus', v.cve, { s: 1, w: 1 }) }], vs)}</div>`;
    else if (t === 'sast') body = h`${scanBtn('sast')}<div class="card flat">${ui.table([{ h: 'Check', f: r => r[0] }, { h: 'Finding', f: r => r[1] }, { h: 'Location', f: r => r[2] }, { h: 'Sev', f: r => ui.sev(r[3]) }, { h: '', f: r => ui.btn('Ticket', 'sec.ticket', r[0], { s: 1, w: 1 }) }], D.scans.sast)}</div><p class="mut">Runs on generated Terraform/Ansible before apply (see IaC Generator).</p>`;
    else if (t === 'image') body = h`${scanBtn('image')}<div class="card flat">${ui.table([{ h: 'Image', f: r => r[0] }, { h: 'Worst', f: r => ui.sev(r[1]) }, { h: 'Critical', num: 1, f: r => r[2] }, { h: 'Total CVEs', num: 1, f: r => r[3] }, { h: 'Deploy gate', f: r => r[2] ? ui.badge('BLOCKED', 'bad') : ui.badge('allowed', 'ok') }], D.scans.image)}</div>`;
    else if (t === 'secrets') body = h`${scanBtn('secrets')}<div class="card flat">${ui.table([{ h: 'Secret', f: r => r[0] }, { h: 'Where', f: r => r[1] }, { h: 'Sev', f: r => ui.sev(r[2]) }, { h: 'Detected by', f: r => r[3] }, { h: '', f: r => ui.btn('Revoke & rotate', 'sec.ticket', r[1], { s: 1, w: 1 }) }], D.scans.secrets)}</div>`;
    else if (t === 'cis') body = h`${scanBtn('cis')}<div class="grid g3">${ui.kpi('Pass', D.cis.filter(c => c.status === 'PASS').length, '', 'good')}${ui.kpi('Fail', D.cis.filter(c => c.status === 'FAIL').length, '', 'bad')}${ui.kpi('Warn', D.cis.filter(c => c.status === 'WARN').length, '', 'warn')}</div><div class="card flat">${ui.table([{ h: 'Check', f: c => c.id }, { h: 'Description', f: c => c.text }, { h: 'Result', f: c => ui.badge(c.status, c.status === 'PASS' ? 'ok' : c.status === 'FAIL' ? 'bad' : 'warn') }], D.cis)}</div>`;
    else if (t === 'net') body = h`<div class="card flat">${ui.table([{ h: 'Resource', f: r => r.res }, { h: 'Cloud', f: r => r.cloud }, { h: 'Port', f: r => r.port }, { h: 'Source', f: r => ui.badge(r.src, 'bad') }, { h: 'Rule', f: r => r.rule }, { h: '', f: r => ui.btn('Restrict', 'sec.ticket', r.res, { s: 1, w: 1 }) }], D.exposure, { empty: 'No exposed ports found.' })}</div>`;
    else body = h`${scanBtn('dast')}<div class="card flat">${ui.table([{ h: 'URL', f: r => r[0] }, { h: 'Finding', f: r => r[1] }, { h: 'Sev', f: r => ui.sev(r[2]) }], D.scans.dast)}</div>`;
    return h`<div class="ph"><div class="grow"><h1>Security &amp; Vulnerability</h1><p class="sub">SAST · image scanning · secret detection · CIS runtime posture · network exposure · DAST · CVE dashboard.</p></div></div>
      ${ui.tabs('security', [['cve', 'CVE dashboard'], ['sast', 'SAST (IaC)'], ['image', 'Image scan'], ['secrets', 'Secrets'], ['cis', 'CIS / kube-bench'], ['net', 'Network exposure'], ['dast', 'DAST']], t)}${body}`;
  } });

  /* ================= COMPLIANCE ================= */
  COC.actions['cp.mode'] = a => { const [id, on] = a.split('|'); const p = D.policies.find(x => x.id === id); p.mode = on === 'true' ? 'enforce' : 'audit'; COC.audit('Policy mode → ' + p.mode, id); COC.refresh(); };
  COC.actions['cp.rego'] = id => { const p = D.policies.find(x => x.id === id); COC.modal({ title: p.id + ' (Rego)', body: ui.pre(p.rego), actions: [{ label: 'Close' }] }); };
  COC.actions['cp.report'] = () => {
    const lines = [`COMPLIANCE REPORT – ${COC.state.tenant}`, `Generated ${new Date().toISOString()}`, '', ...D.frameworks.map(f => `${f.name.padEnd(16)} ${f.score}%  (${f.controls} controls)`), '', 'Policy violations:', ...D.policies.map(p => `  ${p.id.padEnd(22)} ${p.mode.padEnd(8)} ${p.violations}`)];
    COC.audit('Compliance report generated', COC.state.tenant); COC.download('compliance-report.txt', lines.join('\n')); COC.toast('Report downloaded', 'ok');
  };
  COC.actions['cp.csv'] = () => { COC.download('audit-trail.csv', COC.csv([['time', 'user', 'role', 'tenant', 'action', 'target'], ...COC.auditLog.map(a => [a.t.toISOString(), a.user, a.role, a.tenant, a.action, a.target])]), 'text/csv'); };
  COC.actions['cp.fix'] = id => { const p = D.policies.find(x => x.id === id); p.violations = Math.max(0, p.violations - 3); COC.audit('Auto-remediation run for policy', id); COC.toast('Remediated 3 violations of ' + id, 'ok'); COC.refresh(); };
  COC.register({ id: 'compliance', name: 'Compliance & Governance', icon: '📋', phase: 3, roles: SEC, render() {
    const t = COC.tabs.compliance || 'fw';
    let body;
    if (t === 'fw') body = h`<div class="grid g3">${D.frameworks.map(f => h`<div class="card"><h2>${f.name}</h2><div class="kpi"><div class="v ${f.score < 70 ? 'bad' : f.score < 80 ? 'warn' : 'good'}">${f.score}%</div></div>${ui.bar(f.score)}<p class="mut">${Math.round(f.controls * f.score / 100)}/${f.controls} controls passing</p></div>`)}</div><div class="card"><h2>Control mapping</h2><p class="mut">Each OPA policy maps to controls across frameworks (e.g. <code>no-public-s3</code> → CIS 2.1.5, SOC2 CC6.1, PCI 1.3, HIPAA 164.312).</p></div>`;
    else if (t === 'pol') body = h`<div class="card flat">${ui.table([{ h: 'Policy', f: p => h`<b>${p.id}</b><div class="mut">${p.name}</div>` }, { h: 'Enforce?', f: p => ui.sw(p.mode === 'enforce', 'cp.mode', p.id) }, { h: 'Violations', num: 1, f: p => p.violations ? ui.badge(p.violations, 'bad') : ui.badge('0', 'ok') }, { h: '', f: p => h`<div class="row">${ui.btn('View Rego', 'cp.rego', p.id, { s: 1 })}${p.violations ? ui.btn('Remediate', 'cp.fix', p.id, { s: 1, w: 1 }) : ''}</div>` }], D.policies)}</div><p class="mut">Enforced policies block non-compliant IaC in the IaC Generator.</p>`;
    else if (t === 'rep') body = h`<div class="card"><h2>Automated compliance report – ${COC.state.tenant}</h2><p>Frameworks: ${D.frameworks.map(f => f.name).join(', ')}</p><button class="btn p" data-act="cp.report">⬇ Generate &amp; download</button></div>`;
    else body = h`<div class="row" style="margin-bottom:8px"><button class="btn" data-act="cp.csv">⬇ Export CSV</button><span class="mut">${COC.auditLog.length} events this session</span></div><div class="card flat">${ui.table([{ h: 'Time', f: a => a.t.toLocaleTimeString() }, { h: 'User', f: a => a.user }, { h: 'Role', f: a => a.role }, { h: 'Tenant', f: a => a.tenant }, { h: 'Action', f: a => a.action }, { h: 'Target', f: a => a.target }], COC.auditLog, { empty: 'No actions recorded yet – click around in other modules and come back.' })}</div>`;
    return h`<div class="ph"><div class="grow"><h1>Compliance &amp; Governance</h1><p class="sub">Policy-as-code (OPA/Gatekeeper), framework mapping, tenant reports, deployment blocking and a full audit trail.</p></div></div>
      ${ui.tabs('compliance', [['fw', 'Frameworks'], ['pol', 'Policy as code'], ['rep', 'Reports'], ['audit', 'Audit trail']], t)}${body}`;
  } });

  /* ================= IAM ================= */
  COC.actions['iam.fix'] = id => { const o = D.overpriv.find(x => x.id === id); o.fixed = true; COC.audit('Least-privilege applied', o.who); COC.toast(o.who + ' reduced to: ' + o.needs, 'ok'); COC.refresh(); };
  COC.actions['iam.off'] = id => { const o = D.stale.find(x => x.id === id); o.off = true; COC.audit('Stale account disabled', o.who); COC.refresh(); };
  COC.actions['iam.rv'] = a => { const [id, d] = a.split(':'); D.review.find(x => x.id === id).decision = d; COC.audit('Access review: ' + d, D.review.find(x => x.id === id).who); COC.refresh(); };
  COC.actions['iam.jit'] = () => COC.modal({ title: 'Request time-limited privileged access', body: h`<label class="f">Role${ui.select('j-role', ['AWS Admin', 'Azure Owner', 'OCP cluster-admin', 'GCP Editor'], 'AWS Admin', 'noop')}</label><label class="f">Duration${ui.select('j-dur', ['30 min', '1 hour', '4 hours'], '1 hour', 'noop')}</label><label class="f">Reason / ticket<input id="j-why" placeholder="INC-… or CHG-…"></label>`, actions: [{ label: 'Cancel' }, { label: 'Request', primary: true, fn: () => { const w = COC.v('j-why').trim(); if (!w) { COC.toast('A ticket/reason is required', 'bad'); return false; } const m = { '30 min': 30, '1 hour': 60, '4 hours': 240 }[COC.v('j-dur')]; D.jit.push({ id: 'j' + Date.now(), who: 'jayant', role: COC.v('j-role'), why: w, left: m }); COC.audit('JIT access granted', COC.v('j-role') + ' / ' + w); COC.toast('Granted for ' + COC.v('j-dur') + ' – auto-revokes', 'ok'); COC.refresh(); } }] });
  COC.actions['iam.revoke'] = id => { D.jit = D.jit.filter(x => x.id !== id); COC.audit('JIT access revoked early', id); COC.refresh(); };
  COC.register({ id: 'iam', name: 'IAM Governance', icon: '🔑', phase: 3, roles: SEC, render() {
    const t = COC.tabs.iam || 'over', open = D.overpriv.filter(x => !x.fixed).length, st = D.stale.filter(x => !x.off).length, pend = D.review.filter(x => !x.decision).length;
    const score = Math.max(20, 100 - open * 9 - st * 4 - pend * 2);
    let body;
    if (t === 'over') body = h`<div class="card flat">${ui.table([{ h: 'Identity', f: o => o.who }, { h: 'Cloud', f: o => o.cloud }, { h: 'Type', f: o => o.kind }, { h: 'Has', f: o => ui.badge(o.has, 'bad') }, { h: 'Actually needs', f: o => o.needs }, { h: '', f: o => o.fixed ? ui.badge('fixed', 'ok') : ui.btn('Apply least-privilege', 'iam.fix', o.id, { s: 1, p: 1, w: 1 }) }], D.overpriv)}</div>`;
    else if (t === 'stale') body = h`<div class="card flat">${ui.table([{ h: 'Account', f: o => o.who }, { h: 'Cloud', f: o => o.cloud }, { h: 'Inactive', num: 1, f: o => o.days + ' days' }, { h: '', f: o => o.off ? ui.badge('disabled', 'ok') : ui.btn('Disable', 'iam.off', o.id, { s: 1, w: 1 }) }], D.stale)}</div>`;
    else if (t === 'rev') body = h`<div class="card"><h2>Q4 access certification campaign ${ui.badge(pend + ' pending', pend ? 'warn' : 'ok')}</h2>${ui.table([{ h: 'User', f: o => o.who }, { h: 'Access', f: o => o.access }, { h: 'Manager', f: o => o.mgr }, { h: 'Decision', f: o => o.decision ? ui.badge(o.decision, o.decision === 'certified' ? 'ok' : 'bad') : h`<div class="row">${ui.btn('Certify', 'iam.rv', o.id + ':certified', { s: 1, w: 1 })}${ui.btn('Revoke', 'iam.rv', o.id + ':revoked', { s: 1, d: 1, w: 1 })}</div>` }], D.review)}</div>`;
    else body = h`<div class="row" style="margin-bottom:10px"><button class="btn p" data-act="iam.jit" data-w>＋ Request JIT access</button></div><div class="card flat">${ui.table([{ h: 'Who', f: o => o.who }, { h: 'Role', f: o => o.role }, { h: 'Reason', f: o => o.why }, { h: 'Expires in', f: o => ui.badge(o.left + ' min', o.left < 45 ? 'warn' : 'info') }, { h: '', f: o => ui.btn('Revoke', 'iam.revoke', o.id, { s: 1, d: 1, w: 1 }) }], D.jit, { empty: 'No active privileged grants.' })}</div>`;
    return h`<div class="ph"><div class="grow"><h1>IAM Governance</h1><p class="sub">Posture across AWS · Azure · GCP · OpenShift: over-privilege, stale accounts, access reviews and just-in-time grants.</p></div></div>
      <div class="grid g4">${ui.kpi('IAM posture score', score, '', score < 70 ? 'bad' : 'good')}${ui.kpi('Over-privileged', open, '', open ? 'bad' : 'good')}${ui.kpi('Stale accounts', st)}${ui.kpi('Reviews pending', pend)}</div>
      ${ui.tabs('iam', [['over', 'Over-privileged'], ['stale', 'Stale accounts'], ['rev', 'Access reviews'], ['jit', 'Privileged / JIT']], t)}${body}`;
  } });

  /* ================= CERTS & SECRETS ================= */
  const CS = { win: 30 };
  COC.actions['ce.win'] = v => { CS.win = +v; COC.refresh(); };
  COC.actions['ce.renew'] = id => { const c = D.certs.find(x => x.id === id); c.days = 90; COC.audit('Certificate renewed', c.name); COC.toast(c.name + ' renewed (90d)', 'ok'); COC.refresh(); };
  COC.actions['ce.rot'] = id => { const s = D.secrets.find(x => x.id === id); s.age = 0; COC.audit('Secret rotated via Vault', s.name); COC.toast(s.name + ' rotated', 'ok'); COC.refresh(); };
  COC.actions['ce.key'] = id => { const k = D.apikeys.find(x => x.id === id); k.days = 90; COC.audit('API key renewed', k.name); COC.refresh(); };
  const dk = d => d <= 7 ? 'bad' : d <= 15 ? 'warn' : d <= 30 ? 'info' : 'ok';
  COC.register({ id: 'certs', name: 'Certificate & Secret Mgmt', icon: '🔒', phase: 2, roles: SEC, render() {
    const cs = COC.byTenant(D.certs).filter(c => c.days <= CS.win).sort((a, b) => a.days - b.days);
    const n = w => COC.byTenant(D.certs).filter(c => c.days <= w).length;
    return h`<div class="ph"><div class="grow"><h1>Certificate &amp; Secret Management</h1><p class="sub">TLS inventory with 30/15/7-day expiry warnings, Vault-backed secret rotation tracking and API key expiry.</p></div></div>
      <div class="grid g4">${ui.kpi('≤ 30 days', n(30), '', 'warn')}${ui.kpi('≤ 15 days', n(15), '', 'warn')}${ui.kpi('≤ 7 days', n(7), 'urgent', 'bad')}${ui.kpi('Total certificates', COC.byTenant(D.certs).length)}</div>
      <div class="card flat"><div class="row" style="padding:12px 14px"><b>Expiring within</b>${[7, 15, 30, 365].map(w => h`<button class="chip ${CS.win === w ? 'on' : ''}" data-act="ce.win" data-arg="${w}">${w === 365 ? 'all' : w + 'd'}</button>`)}</div>${ui.table([{ h: 'Certificate', f: c => c.name }, { h: 'Where', f: c => c.cloud }, { h: 'Issuer', f: c => c.issuer }, { h: 'Tenant', f: c => c.tenant }, { h: 'Days left', num: 1, f: c => ui.badge(c.days + 'd', dk(c.days)) }, { h: '', f: c => ui.btn('Renew', 'ce.renew', c.id, { s: 1, p: c.days <= 15, w: 1 }) }], cs, { empty: 'Nothing expires in this window 🎉' })}</div>
      <div class="grid g2"><div class="card flat"><div style="padding:14px 16px 0"><h2>Secret rotation (HashiCorp Vault)</h2></div>${ui.table([{ h: 'Path', f: s => s.name }, { h: 'Policy', num: 1, f: s => s.policy + 'd' }, { h: 'Age', f: s => h`<div style="width:90px">${ui.bar(s.age / s.policy * 100)}</div>` }, { h: '', f: s => s.age > s.policy ? ui.badge('overdue', 'bad') : '' }, { h: '', f: s => ui.btn('Rotate now', 'ce.rot', s.id, { s: 1, w: 1 }) }], D.secrets)}</div>
      <div class="card flat"><div style="padding:14px 16px 0"><h2>API key expiry</h2></div>${ui.table([{ h: 'Key', f: k => k.name }, { h: 'Expires', num: 1, f: k => ui.badge(k.days + 'd', dk(k.days)) }, { h: '', f: k => ui.btn('Renew', 'ce.key', k.id, { s: 1, w: 1 }) }], D.apikeys)}</div></div>`;
  } });
})();
