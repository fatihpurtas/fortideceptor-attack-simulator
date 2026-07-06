# FortiDeceptor PoC Runner

`INF_Purple` is a generic attack-simulation toolkit to evaluate **FortiDeceptor**
(or any deception/decoy solution) by triggering the decoys and correlating the
alerts they raise with the exact actions sent.

> **Authorized use only.** Run this solely against decoy IPs you own and are
> authorized to test, within a defined PoC scope. Never point it at production
> systems. This is a defensive / security-assessment tool.

## Components

| File | Role |
|------|------|
| `fortideceptor_poc_test.sh` | **Engine**: 16 attack modules (SSH, SMB, RDP, HTTP, SAP, DC/LDAP, camera/RTSP, printer/JetDirect, DB, SNMP, OT/Modbus/S7…). Auto-installs missing tools; every network op is timeout-bounded. |
| `fd_poc_runner.sh` | **Runner**: the command you run. Reads decoys from a CSV/config/CLI, auto-maps modules from the decoy name, auto-detects the local subnet, and consolidates everything into one `MASTER_<date>.csv`. |
| `decoys.example.conf` | Config template (placeholder IPs). |
| `RUNBOOK.txt` | Step-by-step field runbook. |

## Quick start

```bash
chmod +x *.sh

# Easiest: feed a FortiDeceptor "Decoy Status" CSV export
./fd_poc_runner.sh --csv decoy_status.csv --list     # preview the plan
./fd_poc_runner.sh --csv decoy_status.csv --dry-run  # no packets sent
./fd_poc_runner.sh --csv decoy_status.csv            # run

# Or a config file / inline / manual
./fd_poc_runner.sh --config decoys.conf
./fd_poc_runner.sh --decoys "SAP-01:10.0.0.5,10.1.0.5  DC-01:10.0.0.6"
./fd_poc_runner.sh --targets "10.0.0.5" --only ssh,smb,http
```

## Decoy name to module auto-mapping

| Name contains | Modules |
|---|---|
| `sap` | sap, ssh, http, ftp |
| `win / wsrv / dc / domain / srv` | smb, rdp, dc (ldap/kerberos) |
| `ubuntu / linux / nix` | ssh, http, ftp, database |
| `cam / camera / nvr / dvr` | camera (rtsp/onvif), http, telnet |
| `print / iot / jetdirect / hp` | printer (9100/631/515), snmp, http |
| `scada / plc / modbus / ot` | ot (modbus/s7/bacnet) |
| *unknown* | ssh, telnet, ftp, smb, http, rdp, database, snmp |

`recon` + `portscan` are always added. Override per-decoy modules in the config's third column.

## Output & comparison

Each run writes `fd_poc_logs/MASTER_<date>.csv` with columns:
`timestamp, decoy, module, target, port, protocol, action, result`.

To measure coverage, export the FortiDeceptor **Incident** list (filtered by the
attacker/source IP + test time window) to CSV and match against the master CSV
on `decoy IP + service/protocol + time window`. FortiDeceptor aggregates many
actions into fewer incidents, so compare at the decoy+service level, not
row-by-row.

---
Infinitum IT, Purple Team
