#include "core/bt.h"
#include "core/config.h"
#include "core/module.h"
#include "hci_probe.h"

namespace {
using namespace blueboy;

/// BlueFrag (CVE-2020-0022) lives in Android's L2CAP fragment reassembly. This
/// module records the exposure conditions and the largest echo payload the peer
/// accepts, which tells the operator whether reassembly is exercised at all.
class Bluefrag : public Module {
public:
  std::string name() const override { return "bluefrag"; }
  std::string category() const override { return "offensive"; }
  std::string description() const override {
    return "BlueFrag exposure indicator: L2CAP fragmentation reachability";
  }
  std::string cve() const override { return "CVE-2020-0022"; }
  std::string requirements() const override {
    return "reachable peer, lab authorisation";
  }
  bool offensive() const override { return true; }
  std::string impact() const override {
    return "Advisory only: sends two bounded echo probes (32 B and 600 B). It "
           "does not send the malformed fragments that trigger the bug.";
  }

  ModuleResult run(const ModuleContext &ctx) override {
    ModuleResult r;

    const bt::PingStats small = bt::l2ping(ctx.target, 32, 1, 1500);
    const bt::PingStats large = bt::l2ping(ctx.target, 600, 1, 2000);

    r.add(std::string("32 B echo: ") +
          (small.received ? "answered" : "no reply"));
    r.add(std::string("600 B echo: ") +
          (large.received ? "answered (peer reassembles larger payloads)"
                          : "no reply"));

    std::string err;
    const auto services = bt::sdp_services(ctx.target, err);
    if (!services.empty())
      r.add("Peer advertises " + std::to_string(services.size()) +
            " SDP record(s) reachable without pairing");

    const std::string ver = offensive::remote_version(ctx.iface, ctx.target);
    if (!ver.empty())
      r.add("Remote LMP: " + ver);

    r.success = small.received > 0 || large.received > 0;
    r.summary = r.success
                    ? "Peer accepts L2CAP traffic; fragment handling is exposed"
                    : "Peer did not answer L2CAP echo from this adapter";

    r.add("Fixed in Android security level 2020-02-01 and later");
    r.advise("Confirm the Android build date on the peer; BlueFrag needs a "
             "pre-February-2020 stack");
    r.advise("This module never sends the crashing fragment set: reproducing "
             "CVE-2020-0022 requires a modified controller and a crash-tolerant "
             "test device");
    r.advise("Enable 'Bluetooth scanning' only when needed and keep devices "
             "patched");
    return r;
  }
};

REGISTER_MODULE(Bluefrag);
} // namespace
