
# Read our own config data from vault
path "secret/credmanager-api/*" {
  capabilities = ["read"]
}

# Create policies prefixed with credmanager-
path "sys/policy/credmanager-*" {
  capabilities = ["read", "create", "update"]
}

# Issue tokens using the credmanager role
path "auth/token/create/credmanager" {
  capabilities = ["update"]
}
