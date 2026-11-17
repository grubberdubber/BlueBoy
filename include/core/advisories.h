#pragma once
#include <string>
#include <vector>

namespace blueboy {

/// One entry of config/advisories.conf.
struct Advisory {
  std::string key;
  std::string name;
  std::string cves;
  std::string cls;       // rce, info-leak, auth-bypass, hijack, tracking, dos
  std::string severity;  // critical, high, medium, low, info
  std::string match;     // any, sdp, l2cap, rfcomm, fast_pair
  std::vector<std::string> vendors;
  std::string condition;
  std::string fixed;
  std::string refs;
};

/// Parse the advisory database. Unknown sections or fields are reported in
/// `err` but never abort the load; a broken entry is skipped.
std::vector<Advisory> load_advisories(const std::string &path,
                                      std::string &err);

/// 0 = critical ... 4 = info; unknown severities rank last.
int severity_rank(const std::string &severity);

/// True when the advisory applies to the observed fingerprint.
bool advisory_matches(const Advisory &a, bool sdp, bool l2cap, bool rfcomm,
                      bool fast_pair, const std::string &vendor);

} // namespace blueboy
