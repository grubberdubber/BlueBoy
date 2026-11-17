#include "core/bt.h"
#include "core/config.h"
#include "core/module.h"

#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace {
using namespace blueboy;

// Bounded on purpose: the classic dynamic PSM range is 1..31 and only odd
// values are used by profiles, so 16 probes cover it.
constexpr int kMinPsm = 1;
constexpr int kMaxPsm = 31;
constexpr int kMaxProbes = 16;

std::string psm_name(int psm) {
  switch (psm) {
  case 0x0001:
    return "SDP";
  case 0x0003:
    return "RFCOMM";
  case 0x0005:
    return "TCS-BIN";
  case 0x0007:
    return "TCS-BIN-CORDLESS";
  case 0x0009:
    return "BNEP";
  case 0x000b:
    return "HID_Control";
  case 0x000d:
    return "HID_Interrupt";
  case 0x000f:
    return "UPnP";
  case 0x0011:
    return "AVCTP";
  case 0x0013:
    return "AVDTP";
  case 0x0015:
    return "AVCTP_Browsing";
  case 0x0017:
    return "AVDTP_Browsing";
  case 0x0019:
    return "UDI_C-Plane";
  case 0x001b:
    return "ATT";
  case 0x001d:
    return "3DSP";
  case 0x001f:
    return "IPSP";
  default:
    return "unknown";
  }
}

class PsmScan : public Module {
public:
  std::string name() const override { return "psm_scan"; }
  std::string category() const override { return "assessment"; }
  std::string description() const override {
    return "Bounded L2CAP PSM discovery on the classic dynamic range";
  }
  std::string cve() const override { return "CWE-1327"; }
  std::string requirements() const override { return "root or CAP_NET_RAW"; }

  ModuleResult run(const ModuleContext &ctx) override {
    ModuleResult r;

    int first = ctx.config->get_int("l2cap", "first_psm", kMinPsm);
    int last = ctx.config->get_int("l2cap", "last_psm", kMaxPsm);
    const int timeout = ctx.config->get_int("l2cap", "timeout_ms", 400);

    if (first < kMinPsm)
      first = kMinPsm;
    if (last > kMaxPsm)
      last = kMaxPsm;
    if (last < first) {
      r.summary = "Empty PSM range: first_psm is above last_psm";
      r.advise("Set [l2cap] first_psm <= last_psm inside 1..31");
      return r;
    }

    std::vector<std::pair<int, std::string>> open;
    int probes = 0;
    for (int psm = first | 1; psm <= last && probes < kMaxProbes; psm += 2) {
      ++probes;
      if (bt::l2cap_probe(ctx.target, psm, timeout) == 0)
        open.emplace_back(psm, psm_name(psm));
    }

    r.add("Probed " + std::to_string(probes) + " PSM(s) in " +
          std::to_string(first) + ".." + std::to_string(last) +
          " with a " + std::to_string(timeout) + " ms timeout");

    if (open.empty()) {
      r.summary = "No L2CAP PSM accepted a connection on " + ctx.target;
      r.advise("An empty result usually means the peer is out of range, the "
               "adapter lacks CAP_NET_RAW, or it filters dynamic PSMs");
      return r;
    }

    std::ostringstream summary;
    summary << open.size() << " PSM(s) accepted a connection:";
    for (const auto &[psm, label] : open) {
      std::ostringstream line;
      line << "  PSM 0x" << std::hex << psm << std::dec << "  " << label;
      r.add(line.str());
      summary << " 0x" << std::hex << psm << std::dec;
    }

    r.success = true;
    r.summary = summary.str();

    if (open.size() > 0)
      r.add("Only SDP (0x0001) and RFCOMM (0x0003) are expected on a hardened "
            "host; every other open PSM is a service worth identifying");
    r.advise("Close L2CAP PSMs no profile needs; an exposed dynamic PSM widens "
             "the parser surface reachable without pairing");
    r.advise("Cross-check open PSMs against SDP records: a PSM accepting "
             "connections without an SDP entry is usually a hidden service");
    r.advise("Keep the probe budget small during production windows: each probe "
             "opens and closes one channel");
    return r;
  }
};

REGISTER_MODULE(PsmScan);
} // namespace
