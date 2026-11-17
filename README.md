<div align="center">

```
    ____  __           ____
   / __ )/ /_  _____  / __ )____  __  __
  / __  / / / / / _ \/ __  / __ \/ / / /
 / /_/ / / /_/ /  __/ /_/ / /_/ / /_/ /
/_____/_/\__,_/\___/_____/\____/\__, /
                               /____/
```

**Bluetooth security engineering for authorised audits, red-team exercises and blue-team hardening.**

![C++17](https://img.shields.io/badge/C%2B%2B-17-00599C?logo=cplusplus&logoColor=white)
![BlueZ](https://img.shields.io/badge/BlueZ-libbluetooth-0A7BBB)
![platform](https://img.shields.io/badge/platform-Linux-informational?logo=linux&logoColor=white)
![license](https://img.shields.io/badge/license-MIT-green)
![use](https://img.shields.io/badge/use-authorised%20labs%20only-critical)

</div>

---

## ⚠️ Read this first

> **BlueBoy is a dual-use security tool. It is published for one purpose only:
> auditing, testing and hardening Bluetooth devices you own or are explicitly
> authorised to assess — in a lab, in a penetration test with a signed contract,
> or as a defender validating your own stack and configuration.**
>
> * The **author does not accept responsibility for misuse, damage, downtime or
>   data loss** caused by this software. By cloning, building or running it you
>   accept full responsibility for your actions and their consequences.
> * Running these modules against devices you do not own or administer **may be
>   illegal in your country** and is not an authorised use of this project.
> * **Please do not report or remove this repository.** It is not malware, it is
>   not an attack service, and it has no C2, no delivery channel and no
>   credential harvesting. Every active feature is gated behind an explicit
>   `--lab` flag with hard-coded limits, and the project ships documentation on
>   how to *defend* against each finding. If something here worries you, open an
>   issue and it will be addressed.
> * The tool never phones home, never contacts third-party services and never
>   runs anything against a target without an operator decision.

---

## 🧭 What it is

BlueBoy is a C++17 + BlueZ framework that covers the full audit loop:

| Phase | What you get |
| --- | --- |
| **Recon** | BR/EDR inquiry, BLE advertising scan, OUI vendor enrichment, SDP enumeration, bounded L2CAP PSM discovery |
| **Assessment** | L2CAP reachability and RTT, exposed-service rating, CVE applicability from a local advisory database |
| **Privilege review** | Local BlueZ escalation audit (key store, daemon capabilities, D-Bus policy, groups) |
| **Hardening** | Adapter posture, bond-store inventory with legacy/stale key detection |
| **Offensive (lab-gated)** | Bounded availability tests, RFCOMM/AT access, OBEX operations, PIN recovery orchestration, HID payload generation, CVE exposure indicators |
| **Reporting** | Per-module JSON + Markdown, consolidated session report, append-only audit log |

**What it is not:** it is not a malware framework, not a botnet component, not a
credential stealer, and it does not ship working RCE payloads. Where exploitation
needs controller firmware or vendor-specific hardware, the modules say so instead
of pretending.

---

## 📦 Build

Arch Linux:

```bash
sudo pacman -S --needed base-devel cmake bluez bluez-libs systemd-libs
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j"$(nproc)"
```

Debian / Ubuntu:

```bash
sudo apt install build-essential cmake libbluetooth-dev libsystemd-dev
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j"$(nproc)"
```

`libsystemd` is optional: when present, BlueZ is queried through its supported
D-Bus API (`sd-bus`) instead of legacy HCI calls. Without it the build still
works and only the D-Bus adapter query is disabled.

Raw HCI/L2CAP/RFCOMM sockets need privileges, so run with `sudo` or grant
`CAP_NET_RAW`:

```bash
sudo setcap cap_net_raw,cap_net_admin+eip ./build/blueboy
```

---

## 🚀 Quick start

```bash
blueboy -h                       # help
blueboy -l                       # every module, with impact statements
blueboy -s                       # BR/EDR inquiry
blueboy --le-scan                # BLE advertisers
blueboy -m sdp_enum  -t AA:BB:CC:DD:EE:FF
blueboy -m advisory_scan -t AA:BB:CC:DD:EE:FF
blueboy -m bt_privesc            # local privilege audit
blueboy -m link_key_inventory    # bonded-device inventory (root)
blueboy --category hardening     # local posture review
```

Planning and batch work:

```bash
blueboy --check-config                     # validate config, scope and advisory DB
blueboy --scope-check AA:BB:CC:DD:EE:FF    # in/out of scope, no radio
blueboy --dry-run -m psm_scan -t AA:BB:CC:DD:EE:FF
blueboy -m service_audit -L hosts.txt --exclude 'AA:BB:*'
blueboy -q -m bt_privesc                   # results only
```

Reports land in `output/<module>_<timestamp>.{json,md}` plus one
`output/session_<timestamp>.md`.

### Consent, scope and the lab gate

* The first run prints the risk disclosure and requires typing `I ACCEPT`.
  Acceptance is stored in `~/.config/blueboy/.accepted` (0600) and logged in
  `~/.config/blueboy/audit.log`.
* `[scope] enforce = true` plus `allowlist_file` restricts every target. A
  non-matching address aborts with exit code 3 **before a packet is sent**, and
  a missing allowlist fails closed.
* Offensive modules additionally need `--lab`, print their impact, and ask for a
  single `y/N` when a terminal is attached. Non-interactive runs treat the flag
  as the acknowledgement.
* Every ceiling (rate, payload, duration, connections, cycles) lives in
  `src/core/bt.cpp`; a config file can lower it, never raise it.

Exit codes: `0` ok · `1` usage · `2` module failed · `3` scope denied ·
`4` consent required · `5` offensive module without `--lab`.

---

## 🧩 Modules

### Assessment and hardening (always available)

| Module | Category | Target | Purpose |
| --- | --- | --- | --- |
| `discover` | reconnaissance | no | BR/EDR inquiry with names and OUI vendors |
| `le_scan` | reconnaissance | no | BLE advertising scan |
| `sdp_enum` | reconnaissance | yes | SDP records, classes, RFCOMM/L2CAP channels |
| `l2cap_audit` | assessment | yes | 5 × 48 B echo probes: RTT, loss, link quality |
| `psm_scan` | assessment | yes | Bounded L2CAP PSM discovery (16 probes, 1..31) |
| `advisory_scan` | assessment | yes | Matches the fingerprint against `config/advisories.conf` |
| `service_audit` | assessment | yes | Exposure rating per advertised profile |
| `adapter_posture` | hardening | no | Local adapter configuration review |
| `link_key_inventory` | hardening | no | Bond store: key type, age, legacy and stale pairings |
| `bt_privesc` | escalation | no | Local privilege-escalation audit of the stack |

### Offensive pack (`--lab` required)

| Module | Effect |
| --- | --- |
| `bluesmack` | L2CAP echo burst, up to 500 pps / 600 B / 30 s |
| `l2cap_flood` | Holds up to 64 L2CAP channels to test channel-table pressure |
| `braktooth` | Connect/disconnect churn, up to 200 cycles (no malformed LMP) |
| `bluebug` | AT commands over an exposed RFCOMM serial channel |
| `bluesnarf` | Phonebook object read over OBEX, AT fallback |
| `bluejacking` | OBEX Object Push of a generated vCard |
| `bluecrack` | PIN/link-key recovery orchestration on a pairing capture |
| `blueducky` | HID exposure check plus DuckyScript payload generation |
| `blueborne` | Exposure indicator: unauthenticated SDP/L2CAP surface |
| `bluefrag` | Exposure indicator: L2CAP fragmentation reachability |
| `knob` | Exposure indicator: SSP / key-length preconditions |
| `sweyntooth` | Exposure indicator: BLE controller fingerprint |
| `bias` | Exposure indicator: role-switch / bonded-peer preconditions |

The indicator modules fingerprint and assess; they do not transmit the frames
that trigger the bugs, because doing so requires modified controller firmware.
Each module states that limitation in its own output and ships the matching
defensive advice.

---

## 🛰️ Advisory database

CVE coverage is data, not code. `config/advisories.conf` holds one section per
advisory:

```ini
[whisperpair]
name = WhisperPair (Google Fast Pair)
cves = CVE-2025-36911
class = hijack
severity = high
match = fast_pair
vendors = Sony, JBL, Jabra, Marshall, Google
condition = accessory accepts key-based pairing outside pairing mode
fixed = accessory firmware from the vendor; Android bulletin 2026-01
refs = https://whisperpair.eu/
```

`match` accepts `any`, `sdp`, `l2cap`, `rfcomm` or `fast_pair`, with an optional
`vendors` filter against the OUI lookup. Shipping a new CVE is a config edit —
no rebuild. Shipped entries include WhisperPair (CVE-2025-36911), the Apple Core
Bluetooth overflow (CVE-2026-86919), Airoha RACE (CVE-2025-20700..20702) and
PerfektBlue (CVE-2024-45431..45434), plus BlueBorne, BlueFrag, BrakTooth, KNOB,
BIAS and SweynTooth.

---

## 🧪 Tests

```bash
ctest --test-dir build --output-on-failure
```

The suite covers config parsing, allowlist glob matching, lab-gate decisions,
OUI parsing, bond-store parsing, advisory loading and matching, JSON escaping and
report writing. It needs no Bluetooth adapter.

---

## 🛠️ Adding a module

Create `src/modules/<category>/<name>.cpp`, subclass `blueboy::Module`,
implement `run()`, finish with `REGISTER_MODULE(YourClass);` and rebuild (the
source glob uses `CONFIGURE_DEPENDS`).

* Read-only modules leave `offensive()` at `false`.
* Anything that can disrupt or alter a peer sets `offensive() == true` and
  describes the effect in `impact()`.
* External tools run through `bt::run_tool()` with an argv vector — never a
  shell.
* Advisory data belongs in `config/advisories.conf`, not in module code.

---

## 🛡️ Defensive use

Every offensive finding comes with the fix. Typical recommendations the tool
produces:

* Keep `/var/lib/bluetooth` at `0700 root:root` — a readable key store allows
  impersonation of bonded devices.
* Disable discoverable mode outside pairing windows; require confirmation for
  new HID devices.
* Enforce Secure Connections and remove legacy PIN bonds and stale pairings.
* Patch the stack: BlueBorne (Linux 4.13.5+), BlueFrag (Android 2020-02-01),
  WhisperPair and Airoha RACE (accessory firmware), PerfektBlue (BlueSDK update
  from September 2024), Apple Core Bluetooth (iOS 26.7+/27, macOS 15.8+).

---

## 🗺️ Roadmap

- [x] Read-only assessment and reporting
- [x] Lab-gated offensive pack with hard caps
- [x] Local privilege-escalation and bond-store audits
- [x] Data-driven CVE advisory database
- [ ] More hardening modules (pairing policy, profile exposure, fleet baselines)
- [ ] Baseline diffing between sessions
- [ ] JSON output on stdout for CI pipelines

---

## ⚖️ Legal notice

**Use BlueBoy only on devices you own or have prior written authorisation to
assess.** Radio observations can include third-party devices; respect the agreed
rules of engagement and local law.

The offensive pack can drop links, destabilise controllers, read exposed data
and alter peer state. The author and contributors **accept no liability** for
any damage, downtime, data loss, legal consequence or misuse arising from the
use of this software. You are solely responsible for how you run it and for
holding the authorisation required in your jurisdiction.

This project is published in good faith for **security research, authorised
penetration testing, laboratory validation and defensive hardening**. It is not
intended, designed or licensed for attacking third parties, for building attack
infrastructure, or for any activity that interferes with devices outside your
scope. If you believe a specific file crosses that line, please open an issue
instead of requesting removal — the maintainers will review and adjust it.

Licensed under the MIT License — see [LICENSE](LICENSE).
