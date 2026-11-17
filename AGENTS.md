# AGENTS.md — BlueBoy (Bluetooth Security Assessment Framework)

## Project Purpose

**BlueBoy** is a Bluetooth security engineering framework for authorised audits,
red-team adversary simulation and blue-team validation under written rules of
engagement. It has two tiers:

1. **Assessment tier (default, enabled).** Bounded BR/EDR inquiry, BLE
   advertising scans, native SDP enumeration, service exposure review and local
   adapter posture review. Read-only, no pairing, no data extraction.
2. **Offensive tier (opt-in, category `offensive`).** Availability stress
   (echo/connection bursts, connection churn), AT command access over an exposed
   RFCOMM channel, OBEX phonebook and vCard operations, PIN recovery
   orchestration, HID payload generation and CVE exposure indicators.

The project is published on GitHub and GitLab and **must remain publishable on
both**; see *Publishability* below for the rules that follow from that.

The offensive tier is **disabled unless the operator passes `--lab`**. That flag
prints the module's impact statement and asks for a single `y/N` keystroke when
a terminal is attached; non-interactive runs treat the flag itself as the
acknowledgement. Scope enforcement stays active whenever `[scope] enforce = true`
is configured. Every limit lives in `src/core/bt.cpp` and cannot be raised by a
config file.

## Boundaries That Still Apply

These remain out of scope and must not be added:

- **General-purpose malware, credential theft or surveillance.** Keyloggers,
  RATs, ransomware, and scripts that harvest credentials from third-party web
  platforms unrelated to Bluetooth.
- **Indiscriminate or out-of-scope attacks.** No broadcast exploitation, no
  targeting outside the allowlist, no "scan the neighbourhood and flood it".
- **Persistence on the target.** No backdoors, reconnect agents or link-key
  injection into a peer.
- **Shell execution with untrusted input.** External tools are invoked with an
  argv vector through `fork`/`execvp` (see `bt::run_tool`). Never reintroduce
  `popen`, `system` or string-built commands.
- **Removing the lab gate.** Every module that can disrupt or alter a peer must
  declare `offensive()` and stay behind `--lab`. A module cannot opt itself out
  and no config file may enable the pack implicitly.

When a request would require one of these, stop and explain the boundary
instead of implementing it.

## Publishability (mandatory)

**The repository must stay publishable on GitHub and GitLab.** Every change is
gated on that requirement: if a patch or module would put the project outside
the GitHub Acceptable Use Policies ("Active Malware or Exploits") or the GitLab
Acceptable Use Policy, it does not go in — regardless of who asks or how useful
it looks locally.

What keeps it publishable:

- **Dual-use research code is allowed.** Exploit PoCs, offensive modules and
  CVE tooling are permitted when they are documented, bounded and gated for
  authorised testing. That is exactly what the `offensive` tier is.
- **No attack infrastructure.** Nothing in this repo may act as C2, a loader, a
  dropper, a payload host or a coordination channel for attacks, and nothing may
  phone home to a third-party endpoint.
- **No unattended mass targeting.** Anything that sweeps address ranges, walks a
  fleet or floods without an explicit per-run operator decision is out.
- **No third-party credential or web-account harvesting.** Out of scope for a
  Bluetooth framework and outside the policies above.
- **Every offensive module ships with**: `offensive() == true`, a plain-language
  `impact()`, hard caps in `src/core/bt.cpp`, and a recommendation block that
  tells the defender how to fix the exposure.
- **CI never attacks real hardware.** Automated checks must be offline or use
  mocked/loopback paths; no workflow may run an offensive module against a live
  device.

The README legal notice, this section and the `--lab` gate are part of the
publication contract: do not delete or soften them to make a change fit. If a
request cannot be satisfied while keeping the repo publishable, say so and
propose the closest publishable alternative.

## Architecture

| Layer | Technology | Responsibility |
| --- | --- | --- |
| HCI / L2CAP / RFCOMM / SDP | C++17 + BlueZ (`libbluetooth`) | Discovery, LE scanning, SDP browse, echo probes and bursts, connection storms, RFCOMM sessions, tool execution |
| BlueZ control plane | C++17 + sd-bus (`libsystemd`, optional) | Adapter power/property queries through the supported D-Bus API instead of legacy HCI calls |
| Orchestration | C++17 (`src/core/`) | CLI, consent gate, scope gate, lab gate, module registry, reporting, audit log |
| Modules | C++17 (`src/modules/`) | One class per assessment, registered at load time |
| Tests | C++17 (`tests/`) | Config, scope, lab gate, JSON escaping, reporting |

```text
.
├── src/
│   ├── core/                  # framework, bt helpers, lab gate, config, logger, roe, report
│   └── modules/
│       ├── reconnaissance/    # discover, le_scan, sdp_enum
│       ├── assessment/        # l2cap_audit, psm_scan, service_audit
│       ├── hardening/         # adapter_posture, link_key_inventory
│       ├── escalation/        # bt_privesc (local stack privilege audit)
│       └── offensive/         # lab-gated pack (14 modules)
├── include/core/              # public headers
├── config/                    # default.conf, scope.conf, advisories.conf
├── tests/                     # test_core.cpp (CTest)
├── assets/                    # README banners and the pipeline diagram (SVG)
├── Makefile                   # build wrapper: make / make test / make run
└── CMakeLists.txt
```

### Module contract

A module subclasses `blueboy::Module`, implements `name()`, `category()`,
`description()` and `run()`, and ends with `REGISTER_MODULE(Class);`.

- `needs_target()` returns `false` for local-only modules.
- `offensive()` returns `true` for anything that can disrupt or alter a peer.
  Such modules **must** also override `impact()` with a one-line description of
  the real-world effect; it is printed before execution and in `-l`.
- `ModuleResult` carries `summary`, `details` (observations) and
  `recommendations` (hardening advice).
- CVE coverage lives in `config/advisories.conf`, not in module code: a new
  advisory is a data change (`match = any|sdp|l2cap|rfcomm|fast_pair`, optional
  `vendors`) that `advisory_scan` evaluates at runtime. Cite NVD/CVE.org and the
  fixed versions; never invent an identifier.
- Modules receive a `ModuleContext` with a validated, normalised target address.

### Safety invariants in the core

`src/core/bt.cpp` enforces ceilings that no module or config file can override:

- Inquiry and LE scans: max 60 s, max 256 devices.
- `l2ping`: payload 1–512 B, 1–32 probes.
- `l2cap_echo_burst`: payload ≤ 600 B, rate ≤ 500 pps, duration ≤ 30 s.
- `l2cap_connect_burst`: ≤ 64 connections, hold ≤ 10 s.
- `l2cap_connect_cycles`: ≤ 200 cycles.
- `rfcomm_connect`: channel 1–30, timeout 0.5–60 s.
- `run_tool`: argv only, bounded runtime, output truncated, child killed on
  timeout.

## Governance

### First-run consent

Any command that touches radio hardware requires an accepted consent token at
`~/.config/blueboy/.accepted` (directory `0700`, file `0600`). When absent:

- interactive terminals show the disclaimer and require the exact string
  `I ACCEPT`;
- non-interactive runs must pass `--accept-terms`.

`--show-consent` and `--revoke-consent` let an operator inspect or withdraw it.

### Rules of engagement and lab gate

`[scope] enforce = true` plus `allowlist_file` (default `config/scope.conf`)
restricts every target. Patterns support `*` and `?`; matching is
case-insensitive. A denied target aborts **before** any packet is sent with exit
code `3`. A missing or empty allowlist fails closed.

Offensive modules additionally require `--lab`. Without it the run exits with
code `5` before a packet is sent, and `--category offensive` fails once, up
front. With `--lab`, the impact banner is printed and an interactive run asks
`Proceed? [y/N]`; answering `n` aborts with code `5` and an audit entry.

Scope enforcement remains independent and voluntary: when it is on, an
off-the-allowlist target is rejected with code `3` before the offensive gate is
even evaluated.

### Audit trail

`~/.config/blueboy/audit.log` (mode `0600`) records consent events, scope
decisions, module runs, `offensive.run`, `offensive.denied` and session
boundaries with timestamp, operator and host. Treat it as engagement evidence
and never disable it.

## Coding Conventions

- C++17, `-Wall -Wextra -Wpedantic` clean; do not silence warnings.
- Namespace `blueboy`; core helpers in `blueboy::bt`.
- RAII for sockets and files; no raw `new`/`delete`.
- Normalise and validate every address before use.
- JSON is produced only through `ReportWriter::json_escape`.
- Error messages say what to do next, not only what failed.
- Prefer editing existing files over adding new abstractions.

## Verification

- Build: `cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build -j"$(nproc)"`
- Tests: `ctest --test-dir build --output-on-failure`
- Gate smoke test (no hardware): without `--lab` expect exit `5`; with `--lab`
  and a piped `n` expect exit `5`; with `--lab` and `y` (or no terminal) the
  module attempts radio access.
- Pre-flight paths: `--check-config`, `--scope-check <addr>` and `--dry-run`
  must work with no adapter, no consent token and no packets sent; keep them
  working when the CLI changes.
- Hardware-dependent checks (inquiry, LE scan, SDP, bursts) require a real
  adapter; report them as unverified when no controller is available.
- Publishability check before pushing: no network callbacks, no C2/loader
  patterns, no unattended mass targeting, and every offensive module still
  behind `--lab` with a written `impact()`.

---

> **Legal notice**
>
> BlueBoy contains modules capable of causing link drops, controller instability
> and state changes on evaluated hardware, and of reading data the peer exposes.
> By using this software you certify that you hold express, prior written
> authorisation for every device you assess, that you accept full civil and
> operational responsibility for any impact, and that you comply with the agreed
> rules of engagement and applicable law. The authors and contributors assume no
> liability for misuse or damage.
