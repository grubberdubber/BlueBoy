#pragma once
#include <string>
#include <vector>

namespace blueboy {

/// Everything needed to render one module finding.
struct ReportEntry {
  std::string module;
  std::string category;
  std::string cve;
  std::string target;
  std::string summary;
  std::string timestamp;
  bool success = false;
  std::vector<std::string> details;
  std::vector<std::string> recommendations;
};

/// Writes per-module JSON/Markdown reports plus one consolidated session report.
class ReportWriter {
public:
  explicit ReportWriter(std::string dir);

  bool write_module(const ReportEntry &e);
  bool write_session(const std::vector<ReportEntry> &entries,
                     const std::string &iface);

  const std::string &last_path() const { return last_; }
  std::string session_path() const { return session_; }

  /// RFC 8259 compliant string escaping.
  static std::string json_escape(const std::string &in);

private:
  bool ensure_dir(std::string &err) const;
  std::string dir_;
  std::string last_;
  std::string session_;
};

std::string timestamp_compact(); // YYYYMMDD_HHMMSS
std::string timestamp_iso();     // ISO-8601 with local offset

} // namespace blueboy
