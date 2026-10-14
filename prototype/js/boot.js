(function () {
  // sort modules into their canonical order (as in the feature map)
  const order = ['map', 'dashboard', 'cmdb', 'alerting', 'connectors', 'iac', 'configurator', 'openshift', 'security', 'compliance', 'finops', 'iam', 'certs', 'aiops', 'incidents', 'capacity', 'observability', 'images', 'pipelines', 'backup'];
  COC.modules.sort((a, b) => order.indexOf(a.id) - order.indexOf(b.id));
  const NEW = ['security', 'compliance', 'finops', 'iam', 'certs', 'aiops', 'incidents', 'capacity', 'observability', 'images', 'pipelines', 'backup'];
  COC.modules.forEach(m => { m.isNew = NEW.includes(m.id); });
  COC.refresh();
})();
