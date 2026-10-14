/* Mock data for every module. Deterministic (seeded) so screenshots/demos are repeatable. */
(function () {
  const { rng, pick, TENANTS } = COC, r = rng(42), D = COC.data = {};
  const T = TENANTS.slice(1), ri = (a, b) => Math.floor(a + r() * (b - a + 1)), rf = (a, b) => a + r() * (b - a);
  const series = (n, base, vol, trend) => { let v = base; return Array.from({ length: n }, (_, i) => (v = Math.max(1, Math.min(100, v + (r() - .5) * vol + (trend || 0))))); };
  D.series = series; D.ri = ri; D.rf = rf;

  /* ---- CMDB / resources ---- */
  const CL = {
    AWS: { regions: ['us-east-1', 'eu-west-1', 'ap-south-1'], types: ['EC2', 'EKS', 'RDS', 'S3'] },
    Azure: { regions: ['eastus', 'westeurope', 'centralindia'], types: ['VM', 'AKS', 'ACR', 'Azure SQL'] },
    GCP: { regions: ['us-central1', 'europe-west1', 'asia-south1'], types: ['GCE', 'GKE', 'Cloud SQL', 'GCS'] },
    OpenShift: { regions: ['dc-frankfurt', 'dc-dallas'], types: ['Cluster', 'Node', 'Namespace', 'Route'] },
    'IBM Cloud': { regions: ['us-south', 'eu-de'], types: ['VSI', 'IKS', 'COS'] },
  };
  D.clouds = Object.keys(CL); D.cloudMeta = CL;
  const teams = ['payments', 'platform', 'data', 'web', 'ml'], owners = ['a.rao', 's.kim', 'm.garcia', 'j.smith', 'p.nair', 'l.chen'], envs = ['prod', 'prod', 'staging', 'dev'];
  D.teams = teams; D.envs = ['prod', 'staging', 'dev'];
  D.resources = [];
  for (let i = 0; i < 78; i++) {
    const cloud = pick(r, D.clouds), m = CL[cloud], type = pick(r, m.types), env = pick(r, envs), prod = env === 'prod';
    D.resources.push({
      id: 'ci-' + String(1000 + i), name: `${type.toLowerCase().replace(/\s/g, '')}-${pick(r, ['api', 'db', 'web', 'batch', 'cache', 'ml', 'etl'])}-${ri(1, 99)}`,
      cloud, type, region: pick(r, m.regions), env, tenant: pick(r, T), team: pick(r, teams), owner: pick(r, owners), sla: prod ? pick(r, ['Gold', 'Gold', 'Silver']) : 'Bronze',
      cpu: ri(4, 96), mem: ri(10, 94), disk: ri(8, 92), net: ri(1, 400), cost: ri(40, 2600), state: r() < .93 ? 'running' : 'stopped',
      tags: r() < .8 ? { env, team: pick(r, teams), cost_center: 'CC-' + ri(100, 999) } : {}, vulns: ri(0, 14), public: r() < .1, backup: r() < .8, backupAgeH: ri(2, 200), created: `202${ri(3, 6)}-${String(ri(1, 12)).padStart(2, '0')}-${String(ri(1, 28)).padStart(2, '0')}`,
      cpuSeries: series(24, ri(20, 70), 14), history: [], rel: null,
    });
  }
  D.resources.forEach((x, i) => { x.history = [{ t: '2026-09-02', who: x.owner, what: 'Tag env=' + x.env + ' set' }, { t: '2026-08-11', who: 'discovery', what: 'Asset auto-discovered' }]; if (i % 3 === 0) x.history.unshift({ t: '2026-10-07', who: 'terraform', what: 'Instance size changed' }); });

  /* ---- alerting ---- */
  D.rules = [
    ['Pod CrashLoopBackOff', 'k8s.pod.restarts', '>', 5, '5m', 'high', ['Slack', 'PagerDuty']], ['Disk usage > 85%', 'disk.used_pct', '>', 85, '10m', 'high', ['Email', 'Slack']],
    ['Node NotReady', 'k8s.node.ready', '==', 0, '2m', 'critical', ['PagerDuty']], ['CPU sustained high', 'cpu.used_pct', '>', 90, '15m', 'medium', ['Slack']],
    ['Memory pressure', 'mem.used_pct', '>', 92, '10m', 'medium', ['Slack']], ['Spend anomaly +40%', 'cost.daily_delta', '>', 40, '1d', 'medium', ['Email', 'MS Teams']],
    ['Cert expiring < 15d', 'cert.days_left', '<', 15, '1h', 'high', ['Email']], ['Backup older than 48h', 'backup.age_h', '>', 48, '1h', 'medium', ['Email']],
  ].map((x, i) => ({ id: 'r' + i, name: x[0], metric: x[1], op: x[2], thr: x[3], dur: x[4], sev: x[5], channels: x[6], enabled: i !== 4, kind: i === 5 ? 'anomaly' : 'threshold' }));
  D.channels = [{ name: 'Email', target: 'sre-team@example.com', on: true }, { name: 'Slack', target: '#coc-alerts', on: true }, { name: 'PagerDuty', target: 'webhook: events.pagerduty.com', on: true }, { name: 'MS Teams', target: 'Ops channel webhook', on: true }, { name: 'Webhook', target: 'https://hooks.example.com/coc', on: false }];
  const aT = ['Pod CrashLoopBackOff in payments-api', 'Disk usage 91% on db volume', 'Node NotReady', 'CPU 96% for 15m', 'Spend anomaly: +42% vs 7d avg', 'Cert expires in 6 days', 'Backup older than 72h', 'Memory pressure on cache node', 'Public S3 bucket detected', 'Pipeline failed 3x on main', 'API latency p99 > 2s', 'Unusual login from new geo'];
  D.alerts = aT.map((t, i) => { const x = D.resources[ri(0, 77)]; return { id: 'AL-' + (500 + i), title: t, sev: ['critical', 'high', 'high', 'medium', 'medium', 'high', 'medium', 'low', 'high', 'medium', 'high', 'medium'][i], res: x.name, cloud: x.cloud, tenant: x.tenant, since: ri(3, 600), state: i === 11 ? 'ack' : i === 7 ? 'silenced' : 'firing' }; });

  /* ---- connectors ---- */
  D.connectors = [
    { id: 'c1', cloud: 'AWS', name: 'aws-prod-main (acct 4829…)', sdk: 'boto3', scope: 'EC2, EKS, RDS, S3, CloudWatch', status: 'healthy', last: 3, items: 412, phase: 'P1' },
    { id: 'c2', cloud: 'OpenShift', name: 'ocp-prod-01 (Frankfurt)', sdk: 'kubernetes / openshift client', scope: 'Clusters, Nodes, Namespaces, Routes', status: 'healthy', last: 1, items: 268, phase: 'P1' },
    { id: 'c3', cloud: 'Azure', name: 'azure-sub-emea', sdk: 'azure-sdk', scope: 'VMs, AKS, ACR, Monitor', status: 'healthy', last: 6, items: 305, phase: 'P2' },
    { id: 'c4', cloud: 'GCP', name: 'gcp-proj-analytics', sdk: 'google-cloud', scope: 'GCE, GKE, Cloud Monitoring', status: 'degraded', last: 47, items: 190, phase: 'P2' },
    { id: 'c5', cloud: 'IBM Cloud', name: 'ibm-hcc-align', sdk: 'ibm-cloud-sdk', scope: 'VSI, IKS, COS', status: 'healthy', last: 9, items: 84, phase: 'P2' },
  ];

  /* ---- OpenShift ---- */
  D.clusters = [
    { name: 'ocp-prod-01', ver: '4.15.12', nodes: 9, cpu: 71, mem: 64, dc: 'Frankfurt' }, { name: 'ocp-stage-01', ver: '4.14.30', nodes: 5, cpu: 42, mem: 38, dc: 'Dallas' }, { name: 'rosa-eu-02', ver: '4.15.9', nodes: 6, cpu: 58, mem: 61, dc: 'AWS eu-west-1' },
  ];
  D.namespaces = ['payments', 'platform-monitoring', 'ml-serving', 'web-frontend', 'data-etl', 'openshift-logging', 'cloudops-console'].map(n => ({ name: n, cpuReq: ri(2, 28), cpuQ: 32, memReq: ri(8, 120), memQ: 128, pods: ri(4, 48), bad: ri(0, 3), cluster: pick(r, D.clusters).name }));
  D.operators = [['OpenShift Pipelines (Tekton)', 'CI/CD', '1.14', 1], ['OpenShift GitOps (Argo CD)', 'CI/CD', '1.12', 1], ['Red Hat Service Mesh', 'Networking', '2.5', 0], ['OpenShift Logging', 'Observability', '5.9', 1], ['Compliance Operator', 'Security', '1.4', 0], ['Advanced Cluster Security', 'Security', '4.4', 0], ['cert-manager', 'Security', '1.14', 1], ['Strimzi Kafka', 'Streaming', '0.40', 0], ['OpenShift Virtualization', 'Compute', '4.15', 0]].map(x => ({ name: x[0], cat: x[1], ver: x[2], installed: !!x[3] }));
  D.rbac = [['admin-group', 'Group', 'cluster-admin', '*'], ['sre-team', 'Group', 'edit', 'payments'], ['svc-pipeline', 'ServiceAccount', 'admin', 'platform-monitoring'], ['dev-payments', 'Group', 'edit', 'payments'], ['auditors', 'Group', 'view', '*'], ['svc-legacy', 'ServiceAccount', 'cluster-admin', '*'], ['client-acme', 'User', 'view', 'web-frontend']].map(x => ({ subject: x[0], kind: x[1], role: x[2], ns: x[3] }));
  D.routes = [['pay.acme.example', 'payments-api', 'payments', 'edge'], ['shop.globex.example', 'storefront', 'web-frontend', 'edge'], ['ml.internal', 'model-gw', 'ml-serving', 'passthrough'], ['grafana.coc.example', 'grafana', 'platform-monitoring', 'reencrypt'], ['legacy.initech.example', 'legacy-app', 'data-etl', 'none']].map(x => ({ host: x[0], svc: x[1], ns: x[2], tls: x[3] }));

  /* ---- security ---- */
  const pk = ['openssl 3.0.2', 'log4j-core 2.14.1', 'glibc 2.31', 'curl 7.81', 'nginx 1.20', 'spring-core 5.3.17', 'zlib 1.2.11', 'busybox 1.35', 'python 3.8.10', 'node 16.20', 'golang.org/x/net 0.7', 'jackson-databind 2.12'];
  D.vulns = Array.from({ length: 24 }, (_, i) => { const s = pick(r, ['critical', 'high', 'high', 'medium', 'medium', 'low']), x = pick(r, D.resources); return { cve: `CVE-2026-${ri(1000, 9999)}`, sev: s, cvss: s === 'critical' ? rf(9, 10).toFixed(1) : s === 'high' ? rf(7, 8.9).toFixed(1) : s === 'medium' ? rf(4, 6.9).toFixed(1) : rf(1, 3.9).toFixed(1), pkg: pick(r, pk), fixed: r() < .8 ? 'upgrade → ' + pick(r, ['3.0.14', '2.17.2', '2.35', '8.5', '1.24', '5.3.30']) : 'no fix yet', asset: x.name, cloud: x.cloud, tenant: x.tenant, age: ri(1, 120), status: r() < .2 ? 'in-progress' : 'open' }; });
  D.scans = {
    sast: [['CKV_AWS_18', 'S3 bucket without access logging', 'main.tf:42', 'medium'], ['CKV_AWS_24', 'Security group allows 0.0.0.0/0 on port 22', 'network.tf:17', 'critical'], ['CKV_AZURE_35', 'Storage account default network access not denied', 'storage.tf:9', 'high'], ['tfsec:aws-ec2-no-public-ip', 'Instance has public IP', 'ec2.tf:61', 'high'], ['CKV_K8S_16', 'Container is privileged', 'deploy.yaml:28', 'critical'], ['ANS_0012', 'Ansible task runs shell without no_log', 'playbook.yml:33', 'low']],
    image: [['payments-api:2.3.1', 'critical', 3, 11], ['storefront:5.0.0', 'high', 0, 7], ['model-gw:1.8.4', 'medium', 0, 3], ['legacy-app:0.9', 'critical', 6, 24], ['etl-runner:3.2', 'low', 0, 1]],
    secrets: [['AWS access key', 'infra-repo/scripts/deploy.sh:14', 'high', 'GitLeaks'], ['Slack webhook', 'ops-tools/.env.bak', 'medium', 'truffleHog'], ['Private key (RSA)', 'legacy-app/certs/old.pem', 'critical', 'GitLeaks'], ['JWT secret', 'storefront/config.dev.json:3', 'medium', 'truffleHog']],
    dast: [['https://pay.acme.example', 'Missing CSP header', 'low'], ['https://shop.globex.example', 'Reflected XSS on /search?q=', 'high'], ['https://legacy.initech.example', 'TLS 1.0 enabled', 'medium'], ['https://ml.internal', 'Verbose error leaks stack trace', 'medium']],
  };
  D.cis = ['1.1.1 Ensure API server pod spec file permissions 600', '1.2.1 Anonymous auth disabled', '1.2.6 Kubelet certificate authority set', '2.1 etcd cert-file set', '3.2.1 Audit policy configured', '4.1.1 Kubelet service file permissions 600', '4.2.1 Anonymous auth disabled on kubelet', '5.1.1 cluster-admin role only where required', '5.2.2 Minimize privileged containers', '5.3.2 NetworkPolicies defined for all namespaces', '5.7.3 Apply Security Context to Pods'].map((t, i) => ({ id: t.split(' ')[0], text: t.slice(t.indexOf(' ') + 1), status: [1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 2][i] === 1 ? 'PASS' : [1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 2][i] === 2 ? 'WARN' : 'FAIL' }));
  D.exposure = D.resources.filter(x => x.public).slice(0, 6).map(x => ({ res: x.name, cloud: x.cloud, port: pick(r, [22, 3389, 5432, 6379, 80, 443, 9200]), src: '0.0.0.0/0', rule: pick(r, ['sg-open-ingress', 'nsg-any-any', 'fw-allow-all', 'public-bucket-acl']) }));

  /* ---- compliance ---- */
  D.frameworks = [['CIS Benchmarks', 78, 312], ['SOC 2', 84, 64], ['ISO 27001', 71, 114], ['PCI-DSS', 66, 251], ['HIPAA', 80, 75]].map(x => ({ name: x[0], score: x[1], controls: x[2] }));
  D.policies = [['no-public-s3', 'Deny public S3 / blob / GCS buckets', 'package coc.storage\ndeny[msg] { input.public == true; msg := "public bucket" }', 'enforce', 3], ['require-tags', 'All VMs must carry env, team, cost_center tags', 'package coc.tags\ndeny[msg] { not input.tags.cost_center; msg := "missing cost_center" }', 'enforce', 17], ['no-ssh-world', 'Block 0.0.0.0/0 on port 22 / 3389', 'package coc.net\ndeny[msg] { input.ingress.cidr == "0.0.0.0/0"; input.ingress.port == 22 }', 'enforce', 2], ['encrypt-at-rest', 'Volumes & DBs must be encrypted', 'package coc.enc\ndeny[msg] { input.encrypted == false }', 'enforce', 9], ['no-privileged-pods', 'Deny privileged containers (Gatekeeper)', 'package k8s.psp\ndeny[msg] { input.securityContext.privileged }', 'enforce', 4], ['approved-regions', 'Only approved regions', 'package coc.region\ndeny[msg] { not input.region in data.approved }', 'audit', 1]].map(x => ({ id: x[0], name: x[1], rego: x[2], mode: x[3], violations: x[4] }));

  /* ---- finops ---- */
  const days = Array.from({ length: 30 }, (_, i) => 'D' + (i + 1));
  D.days = days;
  D.costSeries = {}; D.clouds.forEach((c, k) => { const base = [1900, 1400, 1100, 950, 400][k]; D.costSeries[c] = days.map((_, i) => Math.round(base * (1 + (r() - .5) * .12) * (c === 'Azure' && i > 25 ? 1.42 : 1))); });
  D.anomalies = [{ id: 'an1', cloud: 'Azure', text: 'Azure spend +42% on D27–D30', why: '3 new D16s_v5 VMs in westeurope (team: ml) + egress spike', delta: '+$2,310/wk', sev: 'high' }, { id: 'an2', cloud: 'AWS', text: 'AWS NAT gateway data processing x3', why: 'eks cluster pulling images through NAT; add VPC endpoints', delta: '+$640/wk', sev: 'medium' }, { id: 'an3', cloud: 'GCP', text: 'BigQuery slot usage spike', why: 'Unpartitioned query repeated hourly by ml-batch', delta: '+$410/wk', sev: 'medium' }];
  D.rightsize = D.resources.filter(x => x.cpu < 20 && x.state === 'running' && ['EC2', 'VM', 'GCE', 'VSI'].includes(x.type)).slice(0, 8).map(x => ({ id: x.id, name: x.name, cloud: x.cloud, tenant: x.tenant, cpu: x.cpu, from: pick(r, ['m5.2xlarge', 'D8s_v5', 'n2-standard-8']), to: pick(r, ['m5.large', 'D2s_v5', 'n2-standard-2']), save: ri(90, 520), done: false }));
  D.commit = [['AWS', 'Compute Savings Plan 1yr', 'No upfront, $11/hr', 3820], ['AWS', 'RDS Reserved (db.r6g.xlarge)', '3 instances', 1240], ['Azure', 'Reserved VM (D4s_v5) 3yr', '9 VMs', 2150], ['GCP', 'Committed Use 1yr (n2)', '48 vCPU', 960], ['IBM Cloud', 'Reserved capacity VSI', '6 VSIs', 410]].map(x => ({ cloud: x[0], what: x[1], detail: x[2], save: x[3], done: false }));
  D.budgets = [['Acme Bank', 18000, 14900, 19800], ['Globex Retail', 12000, 6200, 11300], ['Initech Health', 9000, 8100, 10400], ['IBM Internal', 22000, 11000, 21200]].map(x => ({ tenant: x[0], budget: x[1], spent: x[2], forecast: x[3] }));
  D.chargeback = teams.flatMap(t => ['Acme Bank', 'Globex Retail', 'Initech Health', 'IBM Internal'].map(tn => ({ team: t, tenant: tn, project: t + '-' + pick(r, ['core', 'edge', 'lab']), aws: ri(100, 1800), azure: ri(80, 1400), gcp: ri(0, 900), ocp: ri(50, 700) }))).filter(() => r() < .55);
  D.idle = [['vol-0a9f…', 'Unattached EBS 500GB', 'AWS', 50], ['disk-old-db-snap', 'Unattached managed disk', 'Azure', 38], ['vm-batch-17 (stopped 41d)', 'Stopped VM still billing disks/IP', 'Azure', 112], ['eip-34.22…', 'Unassociated Elastic IP', 'AWS', 4], ['pd-ssd-test-3', 'Unused persistent disk', 'GCP', 72], ['lb-legacy-02', 'Load balancer with 0 targets', 'AWS', 22]].map((x, i) => ({ id: 'idle' + i, res: x[0], what: x[1], cloud: x[2], save: x[3] }));

  /* ---- IAM ---- */
  D.overpriv = [['svc-ci-runner', 'AWS', 'AdministratorAccess', 'ec2:Describe*, s3:GetObject', 'Service account'], ['m.garcia', 'Azure', 'Owner (subscription)', 'Reader + Contributor on rg-web', 'User'], ['sa-analytics@gcp', 'GCP', 'roles/editor', 'bigquery.dataViewer', 'Service account'], ['svc-legacy', 'OpenShift', 'cluster-admin', 'edit on 2 namespaces', 'Service account'], ['p.nair', 'AWS', 'IAMFullAccess', 'none used in 90d', 'User']].map((x, i) => ({ id: 'op' + i, who: x[0], cloud: x[1], has: x[2], needs: x[3], kind: x[4], fixed: false }));
  D.stale = [['j.smith', 'AWS', 212], ['contractor-lee', 'Azure', 187], ['svc-poc-2024', 'GCP', 402], ['l.chen-old', 'OpenShift', 144], ['tmp-audit', 'AWS', 96], ['intern-2025', 'Azure', 130]].map((x, i) => ({ id: 'st' + i, who: x[0], cloud: x[1], days: x[2], off: false }));
  D.review = ['a.rao', 's.kim', 'm.garcia', 'j.smith', 'p.nair', 'l.chen', 'contractor-lee', 'svc-ci-runner'].map((u, i) => ({ id: 'rv' + i, who: u, access: pick(r, ['AWS Admin', 'Azure Contributor', 'OCP edit', 'GCP Viewer']), mgr: pick(r, ['k.owens', 'd.patel']), decision: null }));
  D.jit = [{ id: 'j1', who: 's.kim', role: 'AWS Admin', why: 'INC-2041 hotfix', left: 38 }, { id: 'j2', who: 'a.rao', role: 'OCP cluster-admin', why: 'CHG-118 upgrade', left: 112 }];

  /* ---- certs & secrets ---- */
  D.certs = ['pay.acme.example', 'shop.globex.example', '*.coc.example', 'ml.internal', 'legacy.initech.example', 'api.coc.example', 'vault.coc.example', 'grafana.coc.example', 'sso.ibm-internal.example', 'registry.coc.example', 'ocp-api.dc-fra', 'argocd.coc.example'].map((n, i) => ({ id: 'ce' + i, name: n, cloud: pick(r, D.clouds), issuer: pick(r, ["Let's Encrypt", 'DigiCert', 'Internal CA', 'ACM', 'cert-manager']), days: [6, 12, 29, 58, 3, 91, 140, 22, 200, 14, 330, 45][i], tenant: pick(r, T) }));
  D.secrets = [['db/payments/password', 'Vault', 90, 84], ['aws/ci-user/access-key', 'Vault', 60, 71], ['azure/sp-terraform/secret', 'Vault', 180, 40], ['gcp/sa-analytics/key', 'Vault', 90, 95], ['ocp/pull-secret', 'Vault', 365, 120], ['slack/webhook', 'Vault', 365, 30], ['kafka/sasl', 'Vault', 90, 12]].map((x, i) => ({ id: 'se' + i, name: x[0], store: x[1], policy: x[2], age: x[3] }));
  D.apikeys = [['PagerDuty integration', 23], ['ServiceNow OAuth', 9], ['GitHub PAT (ci)', 5], ['Datadog API', 84], ['Jira token', 41]].map((x, i) => ({ id: 'ak' + i, name: x[0], days: x[1] }));

  /* ---- AIOps ---- */
  D.aiSeries = (() => { const base = series(48, 45, 6); const lo = base.map(v => v - 12), hi = base.map(v => v + 12); const obs = base.map((v, i) => i === 33 || i === 34 ? v + 38 : i === 41 ? v - 30 : v + (r() - .5) * 8); return { labels: Array.from({ length: 48 }, (_, i) => String(i % 24).padStart(2, '0') + ':00'), base, lo, hi, obs, marks: [33, 34, 41].map(i => ({ i, v: obs[i], t: 'Anomaly: deviates from learned baseline' })) }; })();
  D.predict = [{ id: 'p1', text: 'Disk on db-payments-17 fills in ~6h at current rate', res: 'db-payments-17', conf: 94, eta: 6, fix: 'Expand volume +200GB' }, { id: 'p2', text: 'Memory exhaustion on cache node in ~19h (leak pattern)', res: 'redis-cache-3', conf: 81, eta: 19, fix: 'Restart rolling + raise limit' }, { id: 'p3', text: 'Cert pay.acme.example expires before next deploy window', res: 'pay.acme.example', conf: 99, eta: 144, fix: 'Renew via cert-manager' }, { id: 'p4', text: 'EKS node pool exhausted in ~2d at current growth', res: 'eks-prod-eu', conf: 72, eta: 48, fix: 'Scale node group +3' }];
  D.storm = { raw: 47, incident: 'INC-2051', root: 'Network partition: eu-west-1 NAT gateway degraded', events: [['02:11', 'AWS', 'NAT gateway packet loss', 1], ['02:12', 'AWS', 'EKS pods Pending (image pull timeout)', 0], ['02:13', 'OpenShift', 'payments-api readiness failing', 0], ['02:13', 'Azure', 'Cross-cloud API timeout to AWS', 0], ['02:14', 'GCP', 'ml-batch job retries', 0], ['02:15', 'AWS', 'p99 latency alarm (storefront)', 0]] };
  D.runbooks = [['RB-01', 'Restart crashlooping deployment', 'k8s', 4], ['RB-02', 'Expand cloud disk volume', 'cloud', 6], ['RB-03', 'Rotate leaked credential', 'security', 9], ['RB-04', 'Failover DB replica', 'database', 12], ['RB-05', 'Scale node group', 'k8s', 5], ['RB-06', 'Renew TLS certificate', 'security', 3]].map(x => ({ id: x[0], name: x[1], tag: x[2], mins: x[3] }));

  /* ---- incidents / change ---- */
  D.stages = ['Open', 'Assigned', 'Resolved', 'Post-mortem'];
  D.incidents = [['INC-2050', 'Storefront search latency regression', 'high', 0, 'Globex Retail'], ['INC-2049', 'Storefront search XSS reported', 'high', 1, 'Globex Retail'], ['INC-2047', 'ETL job failing nightly', 'medium', 1, 'Initech Health'], ['INC-2044', 'Grafana datasource timeouts', 'low', 2, 'IBM Internal'], ['INC-2038', 'Cert expiry on legacy host', 'high', 3, 'Initech Health'], ['INC-2031', 'Cluster autoscaler flapping', 'medium', 3, 'IBM Internal']].map(x => ({ id: x[0], title: x[1], sev: x[2], stage: x[3], tenant: x[4], owner: x[3] ? pick(r, owners) : '—', ext: x[3] > 0 ? 'SNOW-' + ri(10000, 99999) : '', notes: [] }));
  D.changes = [['CHG-131', 'Upgrade ocp-stage-01 to 4.15', 'Dallas', 'medium', 'pending', 3, 'Acme Bank'], ['CHG-130', 'Resize payments RDS to r6g.2xlarge', 'AWS', 'high', 'pending', 6, 'Acme Bank'], ['CHG-129', 'Add Azure NSG rule for partner VPN', 'Azure', 'medium', 'approved', 9, 'Globex Retail'], ['CHG-128', 'Rotate Vault root token', 'Vault', 'high', 'pending', 11, 'IBM Internal'], ['CHG-127', 'Enable Gatekeeper enforce mode', 'OCP', 'medium', 'approved', 14, 'Initech Health'], ['CHG-126', 'Decommission legacy VMs', 'Azure', 'low', 'rejected', 17, 'Initech Health'], ['CHG-125', 'GKE node pool upgrade', 'GCP', 'low', 'approved', 22, 'Globex Retail']].map(x => ({ id: x[0], title: x[1], target: x[2], risk: x[3], status: x[4], day: x[5], tenant: x[6], gates: { peer: x[4] !== 'pending' || r() < .5, policy: true, cab: x[4] === 'approved' } }));
  D.sla = [['Payments API', 99.95, 99.97, 'Acme Bank'], ['Storefront', 99.9, 99.82, 'Globex Retail'], ['Patient portal', 99.99, 99.95, 'Initech Health'], ['CoC platform', 99.9, 99.94, 'IBM Internal'], ['ML gateway', 99.5, 99.71, 'IBM Internal'], ['Data ETL', 99.0, 98.4, 'Initech Health']].map(x => ({ svc: x[0], target: x[1], actual: x[2], tenant: x[3] }));
  D.integrations = [{ name: 'ServiceNow', icon: '🟢', desc: 'Incidents & change records two-way sync', on: true }, { name: 'Jira', icon: '🔷', desc: 'Create issues from incidents/findings', on: true }, { name: 'PagerDuty', icon: '🟩', desc: 'On-call paging & escalation', on: false }];

  /* ---- capacity ---- */
  D.headroom = [['ocp-prod-01', 71, 64, 9], ['ocp-stage-01', 42, 38, 5], ['rosa-eu-02', 58, 61, 6], ['eks-prod-eu', 83, 77, 12], ['aks-emea', 49, 55, 8], ['gke-analytics', 66, 52, 7]].map(x => ({ name: x[0], cpu: x[1], mem: x[2], nodes: x[3] }));
  D.capHist = Array.from({ length: 12 }, (_, i) => Math.round(40 + i * 3.1 + (r() - .5) * 4));
  D.scaling = [['eks-prod-eu', 'HPA target CPU 60%, min 6 max 18', 'Peak utilisation 83% → add cluster-autoscaler'], ['ocp-prod-01', 'Enable VPA recommendation mode for payments ns', 'Requests 2.1× actual'], ['aks-emea', 'KEDA scale-to-zero for batch workloads', 'Idle 14h/day']];

  /* ---- observability ---- */
  D.svcs = [['storefront', 120, 60], ['api-gateway', 300, 60], ['payments-api', 480, 160], ['auth', 120, 260], ['inventory', 480, 300], ['orders', 300, 240], ['postgres', 640, 160], ['redis', 640, 280], ['ml-gateway', 120, 160], ['kafka', 480, 40]].map(x => ({ id: x[0], x: x[1], y: x[2], rate: ri(40, 900), err: +(r() * (x[0] === 'payments-api' ? 6 : 1.5)).toFixed(2), p95: ri(20, x[0] === 'payments-api' ? 1900 : 380), spark: series(12, 50, 30) }));
  D.edges = [['storefront', 'api-gateway'], ['api-gateway', 'auth'], ['api-gateway', 'payments-api'], ['api-gateway', 'orders'], ['orders', 'inventory'], ['payments-api', 'postgres'], ['payments-api', 'redis'], ['payments-api', 'kafka'], ['inventory', 'postgres'], ['ml-gateway', 'api-gateway']];
  D.traces = [['a91f…', 'POST /checkout', 1840, 'payments-api'], ['c04b…', 'GET /search', 412, 'inventory'], ['77de…', 'POST /login', 233, 'auth'], ['f2a8…', 'GET /orders/42', 318, 'orders'], ['2e1c…', 'POST /pay', 2210, 'payments-api']].map(x => ({ id: x[0], op: x[1], ms: x[2], svc: x[3] }));
  D.logs = Array.from({ length: 160 }, (_, i) => { const lv = r() < .08 ? 'ERROR' : r() < .2 ? 'WARN' : 'INFO', s = pick(r, D.svcs).id, c = pick(r, ['AWS', 'Azure', 'GCP', 'OpenShift']); return { t: `10:${String(Math.floor(i / 3)).padStart(2, '0')}:${String(ri(0, 59)).padStart(2, '0')}`, lv, svc: s, cloud: c, msg: lv === 'ERROR' ? pick(r, ['connection refused to postgres:5432', 'upstream timeout after 2000ms', 'payment gateway returned 502', 'OOMKilled container restarted']) : lv === 'WARN' ? pick(r, ['retrying request (attempt 2)', 'slow query 1.2s', 'cache miss ratio high']) : pick(r, ['request completed 200', 'healthcheck ok', 'job scheduled', 'token refreshed']) }; });
  D.logAlerts = [{ q: 'level:ERROR AND svc:payments-api', thr: '> 20 / 5m', on: true }, { q: 'msg:"OOMKilled"', thr: '> 0 / 1m', on: true }, { q: 'msg:"connection refused"', thr: '> 10 / 5m', on: false }];

  /* ---- images / SBOM ---- */
  D.images = [['payments-api', '2.3.1', 'ECR', 'prod', 'critical', 11, 'python 3.8'], ['storefront', '5.0.0', 'ACR', 'prod', 'high', 7, 'node 20'], ['model-gw', '1.8.4', 'GCR', 'staging', 'medium', 3, 'python 3.11'], ['legacy-app', '0.9', 'Quay', 'staging', 'critical', 24, 'java 8'], ['etl-runner', '3.2', 'ECR', 'dev', 'low', 1, 'python 3.12'], ['auth-svc', '1.4.2', 'Quay', 'prod', 'medium', 4, 'go 1.22'], ['orders', '4.1.0', 'ACR', 'staging', 'low', 2, 'node 18'], ['inventory', '2.0.7', 'ECR', 'dev', 'medium', 5, 'java 17']].map((x, i) => ({ id: 'im' + i, name: x[0], tag: x[1], reg: x[2], env: x[3], sev: x[4], cves: x[5], rt: x[6], signed: x[4] !== 'critical', promoted: false }));
  D.sbom = [['openssl', '3.0.2', 'Apache-2.0', 'ok'], ['log4j-core', '2.14.1', 'Apache-2.0', 'vuln'], ['spring-core', '5.3.17', 'Apache-2.0', 'ok'], ['mysql-connector', '8.0.28', 'GPL-2.0', 'copyleft'], ['jackson-databind', '2.12.0', 'Apache-2.0', 'vuln'], ['ffmpeg', '4.4', 'LGPL-2.1', 'review'], ['zlib', '1.2.11', 'Zlib', 'ok'], ['readline', '8.1', 'GPL-3.0', 'copyleft'], ['requests', '2.31', 'Apache-2.0', 'ok'], ['lodash', '4.17.21', 'MIT', 'ok']].map(x => ({ pkg: x[0], ver: x[1], lic: x[2], flag: x[3] }));
  D.eol = [['Python 3.8', 'EOL 2024-10', '3 images · payments-api, legacy-app, batch'], ['Java 8', 'Extended support ends 2026-12', '2 images · legacy-app, reports'], ['Node 16', 'EOL 2023-09', '1 image · admin-ui'], ['OpenShift 4.12', 'EOL 2025-07', 'cluster ocp-old-02'], ['Kubernetes 1.26', 'EOL 2024-02', 'aks-emea-legacy']].map(x => ({ rt: x[0], eol: x[1], where: x[2] }));

  /* ---- pipelines & deployments ---- */
  D.pipelines = [['payments-api', 'Tekton', 'success', 214, 4.2], ['storefront', 'GitHub Actions', 'running', 88, 6.1], ['model-gw', 'Jenkins', 'failed', 301, 11.4], ['auth-svc', 'Tekton', 'success', 56, 3.0], ['orders', 'GitHub Actions', 'success', 143, 5.2], ['inventory', 'Jenkins', 'failed', 77, 9.8], ['coc-platform', 'Tekton', 'success', 402, 7.7]].map(x => ({ app: x[0], eng: x[1], status: x[2], run: x[3], mins: x[4] }));
  D.deployClusters = ['ocp-prod-01', 'eks-prod-eu', 'aks-emea', 'gke-analytics'];
  D.apps = ['payments-api', 'storefront', 'auth-svc', 'orders', 'inventory', 'model-gw'];
  D.deploy = {}; D.apps.forEach(a => D.deployClusters.forEach(c => { if (r() < .8) D.deploy[a + '|' + c] = { ver: `${ri(1, 5)}.${ri(0, 9)}.${ri(0, 9)}`, prev: `${ri(1, 4)}.${ri(0, 9)}.${ri(0, 9)}`, ns: pick(r, ['prod', 'prod-a', 'default']), at: '2026-10-' + String(ri(1, 13)).padStart(2, '0'), by: pick(r, owners), healthy: r() < .88 }; }));
  D.deployHist = [];

  /* ---- backup & DR ---- */
  D.drEnvs = [['Production – EU', 82, 24, 3], ['Production – US', 74, 18, 4], ['Staging', 55, 6, 1], ['OCP DR site', 90, 14, 2]].map(x => ({ env: x[0], score: x[1], vms: x[2], gaps: x[3] }));
  D.rto = [['Payments API', 15, 22, 5, 3], ['Storefront', 30, 26, 15, 12], ['Patient portal', 20, 41, 5, 4], ['ML gateway', 120, 75, 60, 45], ['Data warehouse', 240, 190, 30, 55], ['CoC platform', 60, 38, 15, 9]].map(x => ({ svc: x[0], rto: x[1], rtoA: x[2], rpo: x[3], rpoA: x[4] }));
})();
