#include "core/bt.h"
#include "core/config.h"
#include "core/module.h"
#include "hci_probe.h"

namespace {
using namespace blueboy;

/// KNOB (CVE-2019-9506) is an entropy negotiation flaw in the link-key
/// establishment. Forcing a downgrade needs a controller that lets the host
/// rewrite the key-length field of LMP packets; BlueZ does not expose that
/// primitive. The module therefore reports the adapter's exposure and the exact
/// verification procedure instead of pretending to attack.
class Knob : public Module {
public:
  std::string name() const override { return "knob"; }
  std::string category() const override { return "offensive"; }
  std::string description() const override {
    return "KNOB exposure indicator: SSP support and link-key entropy context";
  }
  std::string cve() const override { return "CVE-2019-9506"; }
  std::string requirements() const override {
    return "local adapter information, lab authorisation";
  }
  bool offensive() const override { return true; }
  std::string impact() const override {
    return "Read-only adapter assessment. No link-key downgrade is attempted; "
           "that requires vendor-specific controller instrumentation.";
  }

  ModuleResult run(const ModuleContext &ctx) override {
    ModuleResult r;

    const bt::AdapterInfo ai = bt::adapter_info(ctx.iface);
    if (!ai.error.empty()) {
      r.summary = "Cannot read the local adapter: " + ai.error;
      r.advise("Run with CAP_NET_RAW and confirm the adapter is powered");
      return r;
    }

    r.success = true;
    r.summary = "Adapter " + ai.address + " reviewed: HCI " +
                bt::hci_version_string(ai.hci_version) + ", " +
                (ai.manufacturer.empty() ? "unknown vendor" : ai.manufacturer);

    r.add("Secure Simple Pairing: " +
          std::string(ai.secure_simple_pairing ? "enabled" : "disabled"));
    r.add("HCI version: " + bt::hci_version_string(ai.hci_version));
    r.add("LMP version: " + bt::hci_version_string(ai.lmp_version));

    const std::string ver = offensive::remote_version(ctx.iface, ctx.target);
    if (!ver.empty())
      r.add("Remote LMP: " + ver);

    r.add("KNOB affects the key-length field negotiated during SSP; it needs "
          "an attacker-controlled controller, not a host-side tool");

    if (!ai.secure_simple_pairing)
      r.add("SSP is off: pairing uses legacy PIN, a weaker baseline than the "
            "KNOB scenario");
    else
      r.add("SSP is on: confirm that the kernel carries the key-length "
            "validation fix (Linux 5.2+ / vendor backport)");

    r.advise("Upgrade to a kernel and firmware with the KNOB fix, which rejects "
             "negotiated key lengths below 16 bytes");
    r.advise("Verify with the published procedure on a pair of lab devices "
             "before and after the update");
    r.advise("Treat any device that negotiates a short link key as a finding, "
             "even without a demonstrable attack");
    return r;
  }
};

REGISTER_MODULE(Knob);
} // namespace
