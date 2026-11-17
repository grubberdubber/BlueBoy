#include "core/bt.h"
#include "core/config.h"
#include "core/module.h"
#include "hci_probe.h"

namespace {
using namespace blueboy;

/// SweynTooth (CVE-2020-10061 and the linked set) covers BLE link-layer bugs in
/// several SoCs. It is not reachable from a host stack without patched
/// controller firmware, so this module fingerprints the peer and reports the
/// vendor advisory rather than crafting malformed LL PDUs.
class Sweyntooth : public Module {
public:
  std::string name() const override { return "sweyntooth"; }
  std::string category() const override { return "offensive"; }
  std::string description() const override {
    return "SweynTooth exposure indicator: BLE controller fingerprint";
  }
  std::string cve() const override { return "CVE-2020-10061 family"; }
  std::string requirements() const override {
    return "reachable BLE peer, lab authorisation";
  }
  bool offensive() const override { return true; }
  std::string impact() const override {
    return "Advisory only: passive/limited fingerprinting. No malformed LL "
           "packet is transmitted.";
  }

  ModuleResult run(const ModuleContext &ctx) override {
    ModuleResult r;

    std::string err;
    const auto services = bt::sdp_services(ctx.target, err);
    const std::string ver = offensive::remote_version(ctx.iface, ctx.target);

    r.success = !services.empty() || !ver.empty();
    r.summary = r.success ? "Peer fingerprinted for SweynTooth triage"
                          : "No fingerprint data available from this adapter";

    r.add("SDP records: " + std::to_string(services.size()));
    if (!ver.empty())
      r.add("Remote LMP: " + ver);
    else
      r.add("hcitool unavailable or the peer refused the version request");

    r.add("SweynTooth is a BLE link-layer family: Nordic nRF, TI CC254x, "
          "Cypress, Dialog and Microchip parts are affected depending on "
          "firmware");
    r.add("Triggering it requires raw LL access or patched controller "
          "firmware, which this framework does not provide");

    r.advise("Map the peer's SoC from the manufacturer line and check the "
             "vendor's SweynTooth advisory");
    r.advise("Update the BLE stack firmware; several vendors shipped fixes in "
             "2020 and again in later revisions");
    r.advise("If the device cannot be updated, restrict its BLE role to the "
             "minimum required (peripheral only, no scanning)");
    return r;
  }
};

REGISTER_MODULE(Sweyntooth);
} // namespace
