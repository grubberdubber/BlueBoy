#include "core/bt.h"
#include "core/config.h"
#include "core/module.h"
#include "hci_probe.h"

#include <sstream>

namespace {
using namespace blueboy;

/// BIAS (CVE-2020-10135) abuses the authentication procedure when a device
/// switches roles. Impersonating a bonded peer needs a controller that accepts
/// forged BD_ADDR plus captured link keys, so the module evaluates the local
/// adapter's capability and documents the peer-side conditions.
class Bias : public Module {
public:
  std::string name() const override { return "bias"; }
  std::string category() const override { return "offensive"; }
  std::string description() const override {
    return "BIAS exposure indicator: role-switch and bonded-peer conditions";
  }
  std::string cve() const override { return "CVE-2020-10135"; }
  std::string requirements() const override {
    return "local adapter information, lab authorisation";
  }
  bool offensive() const override { return true; }
  std::string impact() const override {
    return "Read-only assessment. It does not impersonate a bonded device; that "
           "requires a controller with BD_ADDR spoofing and captured keys.";
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
    r.summary = "BIAS preconditions recorded for " + ai.address;

    r.add("Adapter class: 0x" + [&] {
      std::ostringstream s;
      s << std::hex << ai.dev_class;
      return s.str();
    }());
    r.add("SSP: " + std::string(ai.secure_simple_pairing ? "enabled" : "disabled"));
    r.add("BIAS needs a captured link key, a BD_ADDR-spoofing controller and a "
          "peer willing to switch roles after authentication");

    const std::string ver = offensive::remote_version(ctx.iface, ctx.target);
    if (!ver.empty())
      r.add("Remote LMP: " + ver);

    r.advise("Apply the Bluetooth SIG BIAS guidance: reject role switches after "
             "authentication unless the profile requires them");
    r.advise("Update host stacks and controller firmware; BlueZ and the major "
             "vendors shipped fixes in 2020");
    r.advise("Rotate link keys on devices that may have been exposed, and prefer "
             "Secure Connections pairing");
    r.advise("Validating the attack end-to-end needs dedicated hardware; record "
             "this module's output as preconditions, not as proof");
    return r;
  }
};

REGISTER_MODULE(Bias);
} // namespace
