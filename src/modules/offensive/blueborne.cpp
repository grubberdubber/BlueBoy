#include "core/bt.h"
#include "core/config.h"
#include "core/module.h"
#include "hci_probe.h"

namespace {
using namespace blueboy;

/// BlueBorne is a set of stack bugs (CVE-2017-1000250/1000251 among others).
/// This module does not exploit them: it measures the exposure conditions that
/// make them reachable (unauthenticated SDP/L2CAP surface) and asks the
/// operator to confirm the peer's patch level.
class Blueborne : public Module {
public:
  std::string name() const override { return "blueborne"; }
  std::string category() const override { return "offensive"; }
  std::string description() const override {
    return "BlueBorne exposure indicator: unauthenticated SDP/L2CAP surface";
  }
  std::string cve() const override {
    return "CVE-2017-1000250, CVE-2017-1000251, CVE-2017-1000252";
  }
  std::string requirements() const override {
    return "reachable peer, lab authorisation";
  }
  bool offensive() const override { return true; }
  std::string impact() const override {
    return "Advisory only: sends one SDP query and one echo probe. It does not "
           "trigger the memory corruption bugs.";
  }

  ModuleResult run(const ModuleContext &ctx) override {
    ModuleResult r;

    std::string err;
    const auto services = bt::sdp_services(ctx.target, err);
    r.add("SDP records returned: " + std::to_string(services.size()) +
          (err.empty() ? "" : " (" + err + ")"));

    const bt::PingStats st = bt::l2ping(ctx.target, 32, 1, 1500);
    r.add(std::string("L2CAP echo: ") + (st.received ? "answered" : "no reply"));

    const std::string ver = offensive::remote_version(ctx.iface, ctx.target);
    if (!ver.empty())
      r.add("Remote LMP: " + ver);

    const bool reachable = !services.empty() || st.received > 0;
    r.success = reachable;
    r.summary = reachable
                    ? "Peer exposes an unauthenticated baseband/L2CAP surface"
                    : "Peer did not answer SDP or L2CAP from this adapter";

    if (reachable)
      r.add("Reachability is the prerequisite for BlueBorne, not proof of a "
            "vulnerability: the stack version decides that");
    r.add("Fixed in Linux 4.13.5+/4.12.10+, Android 2017-09 security level, "
          "Windows and iOS updates from September 2017");

    r.advise("Confirm the peer's firmware/OS build against the vendor advisory "
             "before rating the finding");
    r.advise("Keep Bluetooth off when not in use and disable discoverable mode "
             "outside pairing windows");
    r.advise("Patch Bluetooth stacks with the vendor security updates; the "
             "BlueBorne fixes are years old and still absent on some embedded "
             "devices");
    return r;
  }
};

REGISTER_MODULE(Blueborne);
} // namespace
