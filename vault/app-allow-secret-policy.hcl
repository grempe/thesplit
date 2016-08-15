path "secret/*" {
    capabilities = ["create", "read", "update", "delete", "list"]
}

path "secret" {
    capabilities = ["list"]
}
