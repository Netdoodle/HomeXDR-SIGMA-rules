# HomeXDR Sigma rules

[Sigma](https://sigmahq.io/) detection rules for homelabs: Docker and Unraid hosts, SSH, DNS
lookups from a resolver's query log (AdGuard Home, Pi-hole, Technitium, Unbound), OPNsense, and
attempts to switch monitoring off. They cover what the community Windows and Linux rule sets leave
out on a home server.

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
| [HomeXDR Agent Stopped Or Removed On Linux](rules/linux/proc_creation_lnx_homexdr_agent_tamper.yml) | high | `pkill`, `systemctl stop`, `plugin remove` or `uninstall` of the agent |
| [HomeXDR Agent Stopped Or Removed On Windows](rules/windows/proc_creation_win_homexdr_agent_tamper.yml) | high | `sc stop`/`delete`, `Stop-Service`, `taskkill` or `uninstall` of the agent service |
| [Sysmon Or Process Auditing Turned Off](rules/windows/proc_creation_win_disable_sysmon_auditing.yml) | high | `sysmon -u`, `auditpol` disabling or clearing, `wevtutil sl ... /e:false` on Sysmon, Security, OpenSSH, PowerShell or Defender logs |
| [Package Installed Inside A Running Container](rules/linux/proc_creation_lnx_container_package_install.yml) | medium | `apk add`, `apt-get install`, `pip install` and similar inside a container after start-up |
| [Download Piped To A Shell Inside A Container](rules/linux/proc_creation_lnx_container_curl_pipe_shell.yml) | high | `curl ... \| sh` and `sh -c "$(wget ...)"` inside a container |
| [Web Application In A Container Started A Shell Or Network Tool](rules/linux/proc_creation_lnx_container_webapp_spawns_shell.yml) | medium | nginx, PHP-FPM, Node.js, Python or Java in a container starting `sh`, `curl`, `nc` and similar |
| [Interactive Shell Opened In A Container](rules/linux/proc_creation_lnx_docker_exec_shell.yml) | low | `docker exec ... sh`, including the Unraid console button |
| [SSH Server Configured To Allow Root Or Password Logins](rules/linux/proc_creation_lnx_sshd_config_weakened.yml) | medium | setting `PermitRootLogin`, `PasswordAuthentication` or `PermitEmptyPasswords` to yes |
| [Unraid User Script Or Cron File Written From The Command Line](rules/linux/proc_creation_lnx_unraid_flash_persistence.yml) | medium | writing a User Scripts script or a plugin `.cron` file on the flash drive |
| [Virtual Machine Defined From The Command Line](rules/linux/proc_creation_lnx_virsh_vm_defined.yml) | low | `virsh define`/`create`/`autostart` and `virt-install` |
| [DNS Lookup Of A DNS-over-HTTPS Provider](rules/dns/dns_query_doh_provider.yml) | low | dns.google, cloudflare-dns.com, Quad9, NextDNS and other DoH servers: the next lookups go around your resolver |
| [DNS Lookup Of A Dynamic DNS Name](rules/dns/dns_query_dynamic_dns.yml) | low | duckdns, no-ip, dynu and other free dynamic DNS names |
| [OPNsense Web GUI Login Failed](rules/network/opnsense_gui_login_failed.yml) | medium | a failed web interface login |
| [OPNsense Web GUI Login](rules/network/opnsense_gui_login.yml) | low | a web interface login |
| [OPNsense Configuration Changed](rules/network/opnsense_config_changed.yml) | low | any configuration change, with user, address and page |
| [Remote Admin Or Database Port Allowed In From The Internet](rules/network/opnsense_inbound_admin_port_allowed.yml) | high | the firewall passing SSH, RDP, VNC, SMB, Telnet, WinRM, Docker or a database port from a public address to a device inside |
| [Windows File Sharing Connection To The Internet](rules/network/opnsense_outbound_smb_to_internet.yml) | medium | the firewall passing port 445 or 139 from inside to a public address |
| [Telnet Connection To The Internet](rules/network/opnsense_outbound_telnet_to_internet.yml) | medium | the firewall passing port 23 or 2323 from inside to a public address, as Mirai-type botnets do |
| [SSH Login Tried For A User That Does Not Exist From Inside The Network](rules/auth/auth_ssh_invalid_user_from_inside.yml) | medium | a failed SSH login for an unknown user name from a private address |
| [DNS Lookup Of A Cryptocurrency Mining Pool](rules/dns/dns_query_crypto_mining_pool.yml) | high | nanopool, supportxmr, moneroocean, 2miners, f2pool, nicehash and other pools |
| [DNS Lookup Of A Remote Desktop Service](rules/dns/dns_query_remote_access_tool.yml) | low | AnyDesk, TeamViewer, RustDesk, ScreenConnect, Splashtop, LogMeIn and similar |

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
| `labels.maintenance` | set by HomeXDR on maintenance work, such as a container's start-up minutes |
| `method` | the login method of an SSH line received over syslog (HomeXDR's syslog decoder) |
| `event.action: ssh-login` | a successful SSH login received over syslog |
| logsource `service: audit`, `Message` | an OPNsense audit log line received over syslog |
| logsource `product: opnsense`, `category: firewall` | an OPNsense filterlog line received over syslog |
| `event.action: pass`, `Protocol`, `SourceIp`, `DestinationIp`, `DestinationPort` | the firewall's action (`pass` or `block`), transport (`tcp`, `udp`) and the connection's addresses and port |
| `event.action: ssh-login-failed` / `ssh_invalid_user`, `event.outcome: failure`, `Message` | a failed SSH login and the sshd log line |

The OPNsense rules need its audit log forwarded: **System → Settings → Logging → Remote**, add
`audit` to the destination's Applications. The audit line formats come from OPNsense's own audit
log; if a rule never fires on yours, open an issue with a sample line.

The three firewall rules only see connections OPNsense logs: turn on logging for your port
forwards and WAN pass rules, and for the LAN rules that let traffic out.

## Tuning

The Docker rules also match what Unraid's Docker manager runs when it recreates a container you
run privileged. In HomeXDR those commands carry `labels.maintenance: docker-update`, and
**Settings → Maintenance** can quiet them. Elsewhere, add a filter on the container name.

## Contributing

Issues and pull requests are welcome. Please include a log line or event that the rule should
match, and one it should not.

## License

Apache License 2.0, like HomeXDR.
