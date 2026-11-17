#pragma once
#include <string>
#include <vector>

namespace blueboy {

/// Rules-of-engagement primitives: first-run consent, target allowlist and an
/// append-only audit trail. These guard every radio operation the tool performs.
class Scope {
public:
  /// Load one pattern per line from `path`; '#' starts a comment.
  bool load_file(const std::string &path, std::string &err);
  void add_pattern(const std::string &pattern);
  bool empty() const { return patterns_.empty(); }
  bool allows(const std::string &bdaddr) const;

  /// Glob matching over normalised BD_ADDRs ("AA:BB:CC:*", "AA:BB:CC:DD:EE:FF").
  static bool glob_match(const std::string &pattern, const std::string &text);

  const std::vector<std::string> &patterns() const { return patterns_; }

private:
  std::vector<std::string> patterns_;
};

/// Path of the persistent consent token: ~/.config/blueboy/.accepted
std::string consent_token_path();
bool consent_recorded(std::string *detail = nullptr);
bool write_consent(std::string &err);
bool revoke_consent();

/// Append one line to ~/.config/blueboy/audit.log (created with mode 0600).
void audit_log(const std::string &event, const std::string &detail);

std::string now_iso8601();
std::string current_user();
std::string host_name();

} // namespace blueboy
