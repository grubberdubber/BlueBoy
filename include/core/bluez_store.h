#pragma once
#include <string>
#include <vector>

namespace blueboy::bluez {

/// One bonded device as recorded by BlueZ. Key material is deliberately not
/// retained: only metadata is exposed, so reports never leak link keys.
struct Bond {
  std::string address;
  std::string name;
  std::string key_type;      // human label for the stored key type
  bool has_link_key = false;
  long long age_days = -1;   // age of the settings file, -1 when unknown
  std::string source;        // path of the settings/info file
};

/// Parse the contents of a BlueZ `settings` (or legacy `info`) file.
/// Returns false when the text carries no recognisable section.
bool parse_settings_text(const std::string &text, Bond &bond);

/// Enumerate the bond store (default /var/lib/bluetooth). `err` is set when the
/// directory is missing or not readable by the current user.
std::vector<Bond> read_bonds(const std::string &store, std::string &err);

/// Human label for a BlueZ LinkKey Type value (0-8).
std::string key_type_label(int type);

} // namespace blueboy::bluez
