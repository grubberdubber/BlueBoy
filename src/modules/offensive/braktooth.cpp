#include "core/bt.h"
#include "core/config.h"
#include "core/module.h"

#include <sstream>

namespace {
using namespace blueboy;

/// Rapid connect/disconnect churn. This stresses the peer's link manager and
/// connection state machine without sending malformed LMP PDUs: it measures
/// resilience, it does not reproduce the published BrakTooth crash frames.
class Braktooth : public Module {
public:
  std::string name() const override { return "braktooth"; }
  std::string category() const override { return "offensive"; }
  std::string description() const override {
    return "Connection churn stress (BrakTooth-class resilience check)";
  }
  std::string cve() const override { return "CVE-2021-28139 family (context)"; }
  std::string requirements() const override {
    return "root or CAP_NET_RAW, lab authorisation";
  }
  bool offensive() const override { return true; }
  std::string impact() const override {
    return "Up to 200 connect/disconnect cycles. Tests whether the peer's link "
           "manager leaks state or refuses later connections.";
  }

  ModuleResult run(const ModuleContext &ctx) override {
    ModuleResult r;
    const int psm = ctx.config->get_int("dos", "churn_psm", 0x0001);
    const int cycles = ctx.config->get_int("dos", "cycles", 40);

    const int ok = bt::l2cap_connect_cycles(ctx.target,
                                            static_cast<uint16_t>(psm), cycles);

    std::ostringstream summary;
    summary << "Completed " << ok << "/" << cycles << " connect/disconnect cycle(s)";
    r.summary = summary.str();
    r.success = ok > 0;

    r.add("Each cycle opens PSM 0x" + [&] {
      std::ostringstream s;
      s << std::hex << psm;
      return s.str();
    }() + ", closes it, then pauses 10 ms");
    r.add("No malformed LMP PDU is generated: this is churn, not a BrakTooth "
          "crash reproduction");
    r.add("Cap: 200 cycles (enforced in bt.cpp)");

    if (ok == 0)
      r.advise("The PSM is closed or the peer is out of range; churn needs at "
               "least one successful connection to be meaningful");
    if (ok > 0 && ok < cycles)
      r.add("The peer started refusing connections after " + std::to_string(ok) +
            " cycle(s)");
    r.advise("A device that stops accepting connections during churn should be "
             "reported against its link manager firmware version");
    r.advise("Reproducing the published crash frames needs a modified "
             "controller; this module deliberately does not do that");
    return r;
  }
};

REGISTER_MODULE(Braktooth);
} // namespace
