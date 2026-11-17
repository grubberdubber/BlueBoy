#include "core/bt.h"
#include "core/module.h"

#include <iomanip>
#include <sstream>

namespace {
using namespace blueboy;

// Fixed, deliberately small probe budget. These values are compile-time
// constants on purpose: the tool must never be able to become a flood tool.
constexpr int kProbePayload = 48; // bytes
constexpr int kProbeCount = 5;    // total echo requests
constexpr int kProbeTimeoutMs = 1500;

std::string quality(double avg_ms, int loss) {
  if (loss > 0)
    return "degraded (packet loss)";
  if (avg_ms < 30.0)
    return "excellent";
  if (avg_ms < 80.0)
    return "good";
  if (avg_ms < 200.0)
    return "elevated";
  return "poor";
}

class L2capAudit : public Module {
public:
  std::string name() const override { return "l2cap_audit"; }
  std::string category() const override { return "assessment"; }
  std::string description() const override {
    return "Bounded L2CAP echo test: reachability, RTT and packet loss";
  }
  std::string requirements() const override { return "root or CAP_NET_RAW"; }

  ModuleResult run(const ModuleContext &ctx) override {
    ModuleResult r;

    const bt::PingStats st =
        bt::l2ping(ctx.target, kProbePayload, kProbeCount, kProbeTimeoutMs);

    if (st.sent == 0) {
      r.summary = "L2CAP echo could not be sent to " + ctx.target;
      r.add("No probe left the local adapter (permissions or adapter state)");
      if (!st.error.empty())
        r.add("Kernel reason: " + st.error);
      r.advise("Run with CAP_NET_RAW and confirm 'bluetoothctl power on'");
      r.advise("If the reason is 'Host is down', the peer is simply not in "
               "range or not answering classic L2CAP; no local fix applies");
      return r;
    }

    const int loss = st.sent - st.received;
    const double loss_pct = 100.0 * loss / st.sent;

    r.success = st.received > 0;
    std::ostringstream summary;
    summary << "L2CAP echo: " << st.received << "/" << st.sent
            << " replies, avg RTT " << std::fixed << std::setprecision(1)
            << st.avg_ms << " ms";
    r.summary = summary.str();

    r.add("Probe budget: " + std::to_string(kProbeCount) + " x " +
          std::to_string(kProbePayload) + " B echo requests (bounded by design)");
    std::ostringstream rtt;
    rtt << "RTT min/avg/max = " << std::fixed << std::setprecision(1)
        << st.min_ms << " / " << st.avg_ms << " / " << st.max_ms << " ms";
    r.add(rtt.str());
    std::ostringstream loss_line;
    loss_line << "Loss = " << std::fixed << std::setprecision(1) << loss_pct
              << "% (" << loss << " probe(s) unanswered)";
    r.add(loss_line.str());
    r.add("Link quality = " + quality(st.avg_ms, loss));

    if (st.received == 0) {
      r.advise("Unanswered echo usually means the peer is out of range, "
               "classic-Bluetooth disabled, or blocking L2CAP echo");
    } else if (loss > 0) {
      r.advise("Investigate packet loss in the 2.4 GHz band (Wi-Fi "
               "interference, distance, low-power mode)");
    } else {
      r.advise("Latency alone is not a vulnerability; record it as a baseline "
               "so future assessments can detect regressions");
    }
    r.advise("Availability stress lives in the separate bluesmack module and "
             "requires --lab; it is not part of this read-only probe");
    return r;
  }
};

REGISTER_MODULE(L2capAudit);
} // namespace
