#include "core/advisories.h"
#include "core/bt.h"
#include "core/config.h"
#include "core/module.h"
#include "core/oui.h"

#include <string>

namespace {
using namespace blueboy;

// Fast Pair advertises this 16-bit service UUID.
constexpr uint16_t kFastPairUuid = 0xFE2C;

class AdvisoryScan : public Module {
public:
  std::string name() const override { return "advisory_scan"; }
  std::string category() const override { return "assessment"; }
  std::string description() const override {
    return "Match the peer fingerprint against the local advisory database";
  }
  std::string cve() const override {
    return "CVE-2025-36911, CVE-2026-86919, CVE-2024-45431..45434, "
           "CVE-2025-20700..20702";
  }
  std::string requirements() const override {
    return "reachable peer; config/advisories.conf";
  }

  ModuleResult run(const ModuleContext &ctx) override {
    ModuleResult r;

    const std::string db = ctx.config->get("advisories", "file",
                                           "config/advisories.conf");
    std::string db_err;
    const auto advisories = load_advisories(db, db_err);
    if (advisories.empty()) {
      r.summary = "No advisory database loaded";
      r.add(db_err.empty() ? "advisory database is empty" : db_err);
      r.advise("Ship config/advisories.conf next to the binary or set "
               "[advisories] file");
      return r;
    }
    if (!db_err.empty()) {
      r.add("Database warnings: " + db_err);
      r.advise("Fix the entries flagged above: a broken section is skipped, so "
               "its advisory is silently missing from the report");
    }

    // Fingerprint: what the peer exposes right now.
    std::string sdp_err;
    const auto services = bt::sdp_services(ctx.target, sdp_err);
    const bt::PingStats echo = bt::l2ping(ctx.target, 32, 1, 1500);

    bool rfcomm = false;
    bool fast_pair = false;
    for (const auto &s : services) {
      if (s.rfcomm_channel >= 0)
        rfcomm = true;
      for (const uint16_t uuid : s.classes)
        if (uuid == kFastPairUuid)
          fast_pair = true;
    }

    const bool sdp = !services.empty();
    const bool l2cap = echo.received > 0;
    const bool reachable = sdp || l2cap;
    const std::string vendor = oui::vendor_for(ctx.target);

    r.add("Fingerprint: SDP=" + std::string(sdp ? "yes" : "no") +
          " L2CAP=" + std::string(l2cap ? "yes" : "no") +
          " RFCOMM=" + std::string(rfcomm ? "yes" : "no") +
          " FastPair=" + std::string(fast_pair ? "yes" : "no"));
    if (!vendor.empty())
      r.add("Vendor (OUI): " + vendor);

    if (!reachable) {
      r.summary = "Peer not reachable; no advisory could be evaluated";
      if (!sdp_err.empty())
        r.add("SDP: " + sdp_err);
      r.advise("Check range, adapter power and CAP_NET_RAW before drawing "
               "conclusions from an empty result");
      return r;
    }

    int applicable = 0;
    for (const auto &a : advisories) {
      if (!advisory_matches(a, sdp, l2cap, rfcomm, fast_pair, vendor))
        continue;
      ++applicable;
      std::string line = "[" + a.severity + "] " + a.name + " (" + a.cves +
                         ", " + a.cls + ")";
      r.add(line);
      if (!a.condition.empty())
        r.add("    when: " + a.condition);
      if (!a.fixed.empty())
        r.add("    fixed: " + a.fixed);
      if (!a.refs.empty())
        r.add("    refs: " + a.refs);
    }

    r.success = applicable > 0;
    r.summary = std::to_string(applicable) + " of " +
                std::to_string(advisories.size()) +
                " advisory(ies) indicated by the fingerprint";

    if (applicable == 0)
      r.add("No entry in the database matches this fingerprint; that is not a "
            "clean bill of health, only an absence of matching rules");
    else
      r.advise("Confirm the peer's build before rating these: an advisory is "
               "applicable when the surface is reachable AND the version is "
               "unpatched");

    r.advise("Update " + db + " as new advisories are published; the module "
                               "reads it at runtime, no rebuild needed");
    r.advise("Treat high/critical matches as patch-pending findings until the "
             "vendor build is confirmed");
    return r;
  }
};

REGISTER_MODULE(AdvisoryScan);
} // namespace
