#include "core/roe.h"
#include "core/logger.h"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <pwd.h>
#include <sstream>
#include <sys/stat.h>
#include <system_error>
#include <unistd.h>

namespace blueboy {

namespace {

constexpr const char *kConsentVersion = "1";

std::string upper(std::string s) {
  for (char &c : s)
    c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
  return s;
}

std::string config_dir() {
  if (const char *xdg = std::getenv("XDG_CONFIG_HOME"); xdg && *xdg)
    return std::string(xdg) + "/blueboy";

  // $HOME wins over the passwd entry so the tool respects sandboxed and
  // test environments.
  if (const char *home = std::getenv("HOME"); home && *home)
    return std::string(home) + "/.config/blueboy";

  if (struct passwd *p = getpwuid(getuid()))
    return std::string(p->pw_dir) + "/.config/blueboy";

  return ".blueboy";
}

} // namespace

// --- Scope -------------------------------------------------------------------

bool Scope::glob_match(const std::string &pattern, const std::string &text) {
  // Simple '*' / '?' glob over upper-cased text. Patterns are short, so the
  // classic two-pointer algorithm is enough.
  const std::string p = upper(pattern);
  const std::string t = upper(text);
  std::size_t pi = 0, ti = 0, star = std::string::npos, mark = 0;

  while (ti < t.size()) {
    if (pi < p.size() && (p[pi] == '?' || p[pi] == t[ti])) {
      ++pi;
      ++ti;
    } else if (pi < p.size() && p[pi] == '*') {
      star = pi++;
      mark = ti;
    } else if (star != std::string::npos) {
      pi = star + 1;
      ti = ++mark;
    } else {
      return false;
    }
  }
  while (pi < p.size() && p[pi] == '*')
    ++pi;
  return pi == p.size();
}

bool Scope::load_file(const std::string &path, std::string &err) {
  std::ifstream f(path);
  if (!f.is_open()) {
    err = "cannot open scope file: " + path;
    return false;
  }

  std::string line;
  while (std::getline(f, line)) {
    auto hash = line.find('#');
    if (hash != std::string::npos)
      line.erase(hash);
    // Trim.
    auto b = line.find_first_not_of(" \t\r\n");
    if (b == std::string::npos)
      continue;
    auto e = line.find_last_not_of(" \t\r\n");
    add_pattern(line.substr(b, e - b + 1));
  }

  if (patterns_.empty()) {
    err = "scope file contains no targets: " + path;
    return false;
  }
  return true;
}

void Scope::add_pattern(const std::string &pattern) {
  if (!pattern.empty())
    patterns_.push_back(upper(pattern));
}

bool Scope::allows(const std::string &bdaddr) const {
  if (bdaddr.empty())
    return false;
  return std::any_of(patterns_.begin(), patterns_.end(),
                     [&](const std::string &p) { return glob_match(p, bdaddr); });
}

// --- Consent -----------------------------------------------------------------

std::string consent_token_path() { return config_dir() + "/.accepted"; }

bool consent_recorded(std::string *detail) {
  std::ifstream f(consent_token_path());
  if (!f.is_open())
    return false;
  if (detail) {
    std::getline(f, *detail);
    if (detail->empty())
      *detail = "(no metadata)";
  }
  return true;
}

bool write_consent(std::string &err) {
  const std::string dir = config_dir();
  std::error_code ec;
  std::filesystem::create_directories(dir, ec);
  if (ec) {
    err = "cannot create " + dir + ": " + ec.message();
    return false;
  }
  ::chmod(dir.c_str(), 0700);

  const std::string path = consent_token_path();
  std::ofstream f(path, std::ios::trunc);
  if (!f.is_open()) {
    err = "cannot write " + path;
    return false;
  }
  f << "version=" << kConsentVersion << "\n"
    << "accepted_at=" << now_iso8601() << "\n"
    << "user=" << current_user() << "\n"
    << "host=" << host_name() << "\n";
  f.close();
  ::chmod(path.c_str(), 0600);
  return true;
}

bool revoke_consent() {
  std::error_code ec;
  return std::filesystem::remove(consent_token_path(), ec);
}

// --- Audit trail -------------------------------------------------------------

std::string audit_log_path() { return config_dir() + "/audit.log"; }

void audit_log(const std::string &event, const std::string &detail) {
  const std::string dir = config_dir();
  std::error_code ec;
  std::filesystem::create_directories(dir, ec);
  if (ec)
    return;

  std::ofstream f(audit_log_path(), std::ios::app);
  if (!f.is_open())
    return;
  ::chmod(audit_log_path().c_str(), 0600);

  f << now_iso8601() << " | " << current_user() << "@" << host_name() << " | "
    << event << " | " << detail << "\n";
}

// --- Environment helpers -----------------------------------------------------

std::string now_iso8601() {
  const auto now = std::chrono::system_clock::now();
  std::time_t t = std::chrono::system_clock::to_time_t(now);
  std::tm tm{};
  localtime_r(&t, &tm);
  std::ostringstream os;
  os << std::put_time(&tm, "%Y-%m-%dT%H:%M:%S%z");
  return os.str();
}

std::string current_user() {
  if (struct passwd *p = getpwuid(getuid()))
    return p->pw_name;
  return "unknown";
}

std::string host_name() {
  char buf[256] = {0};
  if (gethostname(buf, sizeof(buf) - 1) == 0)
    return buf;
  return "unknown";
}

} // namespace blueboy
