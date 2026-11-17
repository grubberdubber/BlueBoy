#include "core/report.h"
#include "core/roe.h"
#include "core/version.h"

#include <chrono>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <sstream>

namespace blueboy {

namespace {

std::string local_time(const char *format) {
  const auto now = std::chrono::system_clock::now();
  std::time_t t = std::chrono::system_clock::to_time_t(now);
  std::tm tm{};
  localtime_r(&t, &tm);
  std::ostringstream os;
  os << std::put_time(&tm, format);
  return os.str();
}

std::string sanitize_filename(const std::string &in) {
  std::string out;
  out.reserve(in.size());
  for (char c : in) {
    const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                    (c >= '0' && c <= '9') || c == '-' || c == '_';
    out.push_back(ok ? c : '-');
  }
  return out.empty() ? "run" : out;
}

std::string json_string_array(const std::vector<std::string> &items,
                              const std::string &indent) {
  if (items.empty())
    return "[]";
  std::ostringstream os;
  os << "[\n";
  for (std::size_t i = 0; i < items.size(); ++i) {
    os << indent << "  \"" << ReportWriter::json_escape(items[i]) << "\"";
    if (i + 1 != items.size())
      os << ',';
    os << '\n';
  }
  os << indent << ']';
  return os.str();
}

} // namespace

std::string timestamp_compact() { return local_time("%Y%m%d_%H%M%S"); }
std::string timestamp_iso() { return now_iso8601(); }

ReportWriter::ReportWriter(std::string dir) : dir_(std::move(dir)) {}

std::string ReportWriter::json_escape(const std::string &in) {
  std::ostringstream os;
  for (unsigned char c : in) {
    switch (c) {
    case '"':
      os << "\\\"";
      break;
    case '\\':
      os << "\\\\";
      break;
    case '\b':
      os << "\\b";
      break;
    case '\f':
      os << "\\f";
      break;
    case '\n':
      os << "\\n";
      break;
    case '\r':
      os << "\\r";
      break;
    case '\t':
      os << "\\t";
      break;
    default:
      if (c < 0x20) {
        os << "\\u" << std::hex << std::setw(4) << std::setfill('0')
           << static_cast<int>(c) << std::dec;
      } else {
        os << static_cast<char>(c);
      }
    }
  }
  return os.str();
}

bool ReportWriter::ensure_dir(std::string &err) const {
  std::error_code ec;
  std::filesystem::create_directories(dir_, ec);
  if (ec) {
    err = "cannot create output directory '" + dir_ + "': " + ec.message();
    return false;
  }
  return true;
}

bool ReportWriter::write_module(const ReportEntry &e) {
  std::string err;
  if (!ensure_dir(err)) {
    return false;
  }

  const std::string base =
      dir_ + "/" + sanitize_filename(e.module) + "_" + e.timestamp;

  std::ofstream js(base + ".json", std::ios::trunc);
  if (!js.is_open())
    return false;
  js << "{\n"
     << "  \"tool\": \"" << kToolName << "\",\n"
     << "  \"version\": \"" << kVersion << "\",\n"
     << "  \"generated_at\": \"" << json_escape(timestamp_iso()) << "\",\n"
     << "  \"host\": \"" << json_escape(host_name()) << "\",\n"
     << "  \"module\": \"" << json_escape(e.module) << "\",\n"
     << "  \"category\": \"" << json_escape(e.category) << "\",\n"
     << "  \"cve\": \"" << json_escape(e.cve) << "\",\n"
     << "  \"target\": \"" << json_escape(e.target) << "\",\n"
     << "  \"success\": " << (e.success ? "true" : "false") << ",\n"
     << "  \"summary\": \"" << json_escape(e.summary) << "\",\n"
     << "  \"details\": " << json_string_array(e.details, "  ") << ",\n"
     << "  \"recommendations\": "
     << json_string_array(e.recommendations, "  ") << "\n"
     << "}\n";
  js.close();

  std::ofstream md(base + ".md", std::ios::trunc);
  if (md.is_open()) {
    md << "## " << e.module << " (" << e.category << ")\n\n"
       << "- **Target:** " << (e.target.empty() ? "(local)" : e.target) << "\n"
       << "- **Status:** " << (e.success ? "ok" : "failed") << "\n"
       << "- **CVE reference:** " << e.cve << "\n\n"
       << "### Summary\n\n" << e.summary << "\n";
    if (!e.details.empty()) {
      md << "\n### Observations\n\n";
      for (const auto &d : e.details)
        md << "- " << d << "\n";
    }
    if (!e.recommendations.empty()) {
      md << "\n### Recommendations\n\n";
      for (const auto &r : e.recommendations)
        md << "- " << r << "\n";
    }
    md << "\n";
    md.close();
  }

  last_ = base + ".json";
  return true;
}

bool ReportWriter::write_session(const std::vector<ReportEntry> &entries,
                                 const std::string &iface) {
  if (entries.empty())
    return false;

  std::string err;
  if (!ensure_dir(err))
    return false;

  const std::string base = dir_ + "/session_" + timestamp_compact();
  session_ = base + ".md";
  for (int n = 2; std::filesystem::exists(session_); ++n)
    session_ = base + "_" + std::to_string(n) + ".md";

  std::ofstream md(session_, std::ios::trunc);
  if (!md.is_open())
    return false;

  md << "# " << kToolName << " Bluetooth assessment report\n\n"
     << "- **Generated:** " << timestamp_iso() << "\n"
     << "- **Operator:** " << current_user() << "@" << host_name() << "\n"
     << "- **Adapter:** " << iface << "\n"
     << "- **Modules executed:** " << entries.size() << "\n\n"
     << "> This report documents observed configuration and exposure, plus the\n"
     << "> gated offensive modules that were run. Every step is bounded by hard\n"
     << "> caps in the core library. Validate findings against the signed\n"
     << "> engagement scope before sharing outside the authorised team.\n\n";

  for (const auto &e : entries) {
    md << "## " << e.module << " (" << e.category << ")\n\n"
       << "- **Target:** " << (e.target.empty() ? "(local)" : e.target) << "\n"
       << "- **Status:** " << (e.success ? "ok" : "failed") << "\n"
       << "- **Reference:** " << e.cve << "\n\n"
       << e.summary << "\n";
    if (!e.details.empty()) {
      md << "\n**Observations**\n\n";
      for (const auto &d : e.details)
        md << "- " << d << "\n";
    }
    if (!e.recommendations.empty()) {
      md << "\n**Recommendations**\n\n";
      for (const auto &r : e.recommendations)
        md << "- " << r << "\n";
    }
    md << "\n---\n\n";
  }

  md << "## Legal and ethical notice\n\n"
     << "BlueBoy combines read-only assessment modules with an offensive pack\n"
     << "that only runs behind --lab, an enforced allowlist and per-target\n"
     << "confirmation. Some offensive modules can disrupt or alter the peer.\n"
     << "Running any of this against systems without prior written\n"
     << "authorisation may be unlawful. The operator is responsible for\n"
     << "respecting the agreed rules of engagement.\n";

  md.close();
  return true;
}

} // namespace blueboy
