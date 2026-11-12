# HomeXDR Sigma rules

[Sigma](https://sigmahq.io/) detection rules for homelabs: Docker and Unraid hosts, SSH, and DNS
lookups from a resolver's query log (AdGuard Home, Pi-hole, Technitium, Unbound). They cover
what the community Windows and Linux rule sets leave out on a home server.

The rules are written for [HomeXDR](https://github.com/Netdoodle/homexdr), which also ships them
built in, and are tested there against matching and lookalike events
(`server/internal/detect/homexdr_rules_test.go`).

## Rules

| Rule | Level | Fires on |
|---|---|---|
| [Nsenter Into The Host's Namespaces](rules/linux/proc_creation_lnx_nsenter_host_namespaces.yml) | high | `nsenter -t 1`: a container breakout, or a root shell outside every limit |
| [Container Started With Host-Level Access](rules/linux/proc_creation_lnx_docker_privileged_container.yml) | medium | `docker run` with `--privileged`, `--pid=host`, `-v /:/`, the Docker socket or `SYS_ADMIN` |
| [Docker Socket Used From Inside A Container](rules/linux/proc_creation_lnx_container_docker_cli_socket.yml) | medium | the docker CLI or `curl --unix-socket docker.sock` inside a container |
| [SSH Authorized Keys Changed From The Command Line](rules/linux/proc_creation_lnx_ssh_authorized_keys_write.yml) | medium | writing, copying or downloading an `authorized_keys` file |
| [Unraid Boot Script Modified](rules/linux/proc_creation_lnx_unraid_go_file_write.yml) | high | writing to `/boot/config/go`, which Unraid runs as root at every boot |
| [Unraid Plugin Installed From A URL](rules/linux/proc_creation_lnx_unraid_plugin_install.yml) | low | `plugin install https://...plg` from outside Unraid's own servers |
| [DNS Lookup Of A Reverse Tunnel Service](rules/dns/dns_query_tunnel_services.yml) | medium | ngrok, Cloudflare quick tunnels, localtunnel, serveo, pinggy, bore |
| [DNS Lookup Of A Tor Onion Or Tor2web Gateway](rules/dns/dns_query_tor_onion.yml) | high | `.onion` names and Tor2web gateways |
| [DNS Lookup Of An Anonymous Paste Or File Upload Service](rules/dns/dns_query_anonymous_file_sharing.yml) | low | transfer.sh, file.io, 0x0.st, pastebin and similar |
| [SSH Login From A Public Address](rules/auth/auth_ssh_login_public_address.yml) | high | a successful SSH login from outside private and Tailscale ranges |
| [Root SSH Login With A Password](rules/auth/auth_ssh_root_password_login.yml) | medium | root or Administrator logging in over SSH with a password |
| [SSH Login With A Key HomeXDR Does Not Know](rules/auth/auth_ssh_login_unnamed_key.yml) | low | a key login whose key has no name in HomeXDR (HomeXDR only) |

## Using them

**In HomeXDR:** they are built in. Using this repository instead keeps them updated
independently of server releases: **Rules → Import rules**, paste
`https://github.com/Netdoodle/HomeXDR-SIGMA-rules`, folder `rules`.

**Elsewhere:** the process rules use the standard Sigma `process_creation` fields (`Image`,
`CommandLine`) and work with any backend. The others use ECS-style field names that HomeXDR
fills in, so map them in your pipeline:

| Field in the rules | Meaning |
|---|---|
| `QueryName` | the looked-up name (`dns.question.name`) |
| `SourceIp`, `User` | the client address and user name of a login |
| `event.action: ssh_login`, `event.outcome: success` | a successful SSH login |
| `auth_method` | `publickey`, `password`, `keyboard-interactive` |
| `container.id` | set when the process runs in a container |
| `labels.ssh_key`, `labels.ssh_key_name` | the key a session used, and its name in HomeXDR |

## Tuning

The Docker rules also match what Unraid's Docker manager runs when it recreates a container you
run privileged. In HomeXDR those commands carry `labels.maintenance: docker-update`, and
**Settings → Maintenance** can quiet them. Elsewhere, add a filter on the container name.

## Contributing

Issues and pull requests are welcome. Please include a log line or event that the rule should
match, and one it should not.

## License

Apache License 2.0, like HomeXDR.
