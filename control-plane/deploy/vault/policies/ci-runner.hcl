# GitHub Actions / GitLab CI / Jenkins AppRoles: only the pipeline secrets they need.
path "secret/data/coc/cicd/*" {
  capabilities = ["read"]
}

path "sys/*" {
  capabilities = ["deny"]
}
path "auth/token/create*" {
  capabilities = ["deny"]
}
path "database/*" {
  capabilities = ["deny"]
}
path "transit-dr-broker/*" {
  capabilities = ["deny"]
}
