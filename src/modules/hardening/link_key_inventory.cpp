#include "core/bluez_store.h"
#include "core/config.h"
#include "core/module.h"

#include <string>

namespace {
using namespace blueboy;

/// Blue-team view of the local bond store: which devices are paired, with what
/// kind of key, and how old the record is. Key material is never read into the
/// report, only the metadata an auditor needs to decide what to prune.
class LinkKeyInventory : public Module {
public:
  std::string name() const override { return "link_key_inventory"; }
  std::string category() const override { return "hardening"; }
  std::string description() const override {
    return "Local bond store inventory: key types, age, stale pairings";
  }
  std::string cve() const override { return "CWE-1188, CWE-613"; }
  std::string requirements() const override {
    return "read access to /var/lib/bluetooth (root for local bonds)";
  }
  bool needs_target() const override { return false; }

  ModuleResult run(const ModuleContext &ctx) override {
    ModuleResult r;

    const std::string store =
        ctx.config->get("bluez", "store", "/var/lib/bluetooth");
    const int stale_days = ctx.config->get_int("bluez", "stale_days", 365);

    std::string err;
    const auto bonds = bluez::read_bonds(store, err);

    if (!err.empty()) {
      r.summary = "Bond store unavailable: " + store;
      r.add(err);
      r.advise("Run as root to inventory local bonds; a bond store you cannot "
               "read is either empty or a permissions finding on its own");
      return r;
    }

    if (bonds.empty()) {
      r.success = true;
      r.summary = "No bonded device recorded in " + store;
      r.advise("Keep it that way outside pairing windows: an empty bond store "
               "leaves nothing to impersonate");
      return r;
    }

    size_t legacy = 0, stale = 0, le_only = 0;
    for (const auto &b : bonds) {
      std::string line = b.address;
      if (!b.name.empty())
        line += "  " + b.name;
      line += "  | key: " +
              (b.has_link_key ? b.key_type : std::string("LE long-term only"));
      if (b.age_days >= 0)
        line += " | " + std::to_string(b.age_days) + " day(s) old";

      if (b.has_link_key && b.key_type == "legacy PIN") {
        ++legacy;
        line += " | LEGACY KEY";
      }
      if (!b.has_link_key)
        ++le_only;
      if (b.age_days >= stale_days) {
        ++stale;
        line += " | STALE";
      }
      r.add(line);
    }

    r.add(std::to_string(bonds.size()) + " bond(s) in " + store);

    r.success = legacy == 0 && stale == 0;
    r.summary = std::to_string(bonds.size()) + " bond(s), " +
                std::to_string(legacy) + " legacy, " +
                std::to_string(stale) + " stale (" + std::to_string(stale_days) +
                " d), " + std::to_string(le_only) + " LE-only";

    if (legacy > 0)
      r.advise("Re-pair devices still holding a legacy PIN key: those keys come "
               "from an entropy-poor PIN and are the first thing an attacker "
               "reuses");
    if (stale > 0)
      r.advise("Remove bonds that have not been used in " +
               std::to_string(stale_days) +
               " days (bluetoothctl remove <MAC>); every stored key is a "
               "credential with no expiry");
    if (le_only > 0)
      r.advise("LE-only bonds depend on the controller's key storage: confirm "
               "the adapter keeps them encrypted and does not expose them "
               "through debug interfaces");
    r.advise("Keep /var/lib/bluetooth 0700 root:root; a readable key store "
             "allows impersonation without breaking pairing");
    return r;
  }
};

REGISTER_MODULE(LinkKeyInventory);
} // namespace
