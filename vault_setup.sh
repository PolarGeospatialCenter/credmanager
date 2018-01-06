vault auth -method ldap
vault mount -path=lvt-ssh ssh
vault write lvt-ssh/config/ca generate_signing_key=true
vault write lvt-ssh/roles/node key_type=ca ttl=72h allow_host_certificates=true allowed_domains="pgc.umn.edu" allow_subdomains=true

vault mount -path=lvt-pki-consul pki
vault mount-tune -max-lease-ttl=87600h lvt-pki-consul
vault write lvt-pki-consul/root/generate/internal common_name=ca.consul ttl=87600h
vault write lvt-pki-consul/config/urls issuing_certificates="https://vault.pgc.umn.edu:8200/v1/pki/ca" crl_distribution_points="https://vault.pgc.umn.edu:8200/v1/pki/crl"
vault write lvt-pki-consul/roles/node allowed_domains=consul allow_subdomains=true max_ttl=72h

vault policy-write credmanager-server vault_policy.hcl
vault write /auth/token/roles/credmanager @vault_credmanager_role.json
