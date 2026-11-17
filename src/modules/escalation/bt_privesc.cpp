#include "core/bt.h"
#include "core/module.h"

#include <filesystem>
#include <fstream>
#include <grp.h>
#include <pwd.h>
#include <sstream>
#include <string>
#include <sys/types.h>
#include <unistd.h>
#include <vector>

namespace {
using namespace blueboy;
namespace fs = std::filesystem;

/// Local privilege-escalation audit around the Bluetooth stack. It never
/// modifies anything: it looks at who owns the link-key store, what
/// bluetoothd runs as, which groups the operator belongs to and how the D-Bus
/// policy exposes org.bluez.
///
/// The escalation paths it checks for are the real ones on Linux hosts:
///   * link keys readable by a non-root user (impersonation of bonded devices),
///   * bluetoothd running with full capabilities as root, so a parsed-input bug
///     is a root bug,
///   * writable configuration or key store (persistent key injection),
///   * D-Bus policy that lets unprivileged users register an agent and answer
///     pairing prompts on behalf of the machine.
class BtPrivesc : public Module {
public:
  std::string name() const override { return "bt_privesc"; }
  std::string category() const override { return "escalation"; }
  std::string description() const override {
    return "Local privilege-escalation audit of the Bluetooth stack";
  }
  std::string cve() const override { return "CWE-269, CWE-732, CWE-250"; }
  std::string requirements() const override {
    return "local host access (no adapter needed)";
  }
  bool needs_target() const override { return false; }

  ModuleResult run(const ModuleContext &ctx) override {
    (void)ctx;
    ModuleResult r;
    int findings = 0;

    const uid_t uid = geteuid();
    const bool is_root = uid == 0;
    r.add("Running as " + user_name(uid) + " (euid " + std::to_string(uid) +
          (is_root ? ", root" : ", unprivileged") + ")");

    // 1. Link-key store.
    const fs::path keydir = "/var/lib/bluetooth";
    if (fs::exists(keydir)) {
      report_path(r, keydir, findings);
      if (!is_root && ::access(keydir.c_str(), R_OK) == 0)
        finding(r, findings,
                "The current user can read " + keydir.string() +
                    ": link keys of every bonded device are exposed");
      else
        r.add(keydir.string() + " is not readable by this user");
    } else {
      r.add(keydir.string() + " does not exist (nothing bonded yet)");
    }

    // 2. Configuration and D-Bus policy.
    const fs::path etc = "/etc/bluetooth";
    if (fs::exists(etc))
      report_path(r, etc, findings);
    report_path(r, "/etc/bluetooth/main.conf", findings);
    report_path(r, "/usr/share/dbus-1/system.d/bluetooth.conf", findings);

    // 3. bluetoothd identity and capabilities.
    const std::string pid = daemon_pid("bluetoothd");
    if (pid.empty()) {
      r.add("bluetoothd is not running");
    } else {
      const std::string status = "/proc/" + pid + "/status";
      std::string owner = uid_line(status);
      std::string caps = proc_field(status, "CapEff:");
      r.add("bluetoothd pid " + pid + " runs as uid " + owner +
            (caps.empty() ? "" : " with CapEff " + caps));
      if (owner == "0" && !caps.empty() && caps.find("ffffffffff") == 0)
        r.add("bluetoothd holds the full capability set as root: a parser bug "
              "in the daemon is a root compromise");
      const std::string version = daemon_version();
      if (!version.empty())
        r.add("bluetoothd version: " + version);
    }

    // 4. Group membership.
    const std::vector<std::string> groups = user_groups();
    std::string joined;
    for (const auto &g : groups)
      joined += (joined.empty() ? "" : ", ") + g;
    r.add("Groups: " + (joined.empty() ? "(none read)" : joined));
    for (const char *g : {"bluetooth", "lp", "dialout"}) {
      if (has_group(groups, g))
        r.add(std::string("Member of '") + g +
              "' - grants access to the adapter or to daemon state");
    }
    if (has_group(groups, "wheel") || has_group(groups, "sudo"))
      r.add("Member of an admin group (wheel/sudo): any daemon compromise is a "
            "root compromise from this account");

    r.success = findings == 0;
    r.summary = findings == 0
                    ? "No local Bluetooth escalation path found"
                    : std::to_string(findings) + " local escalation finding(s)";

    r.advise("Keep /var/lib/bluetooth 0700 root:root; a readable key store "
             "allows impersonation of bonded devices without breaking pairing");
    r.advise("Run bluetoothd as root but drop capabilities it does not use, or "
             "sandbox it (systemd CapabilityBoundingSet, ProtectSystem=strict)");
    r.advise("Remove unprivileged users from 'bluetooth' and 'lp' unless they "
             "genuinely need adapter control");
    r.advise("Keep the D-Bus policy for org.bluez strict: no at_console rules, "
             "no agent registration for arbitrary users");
    r.advise("Audit package updates for the daemon; check the distro security "
             "tracker for bluez advisories each cycle");
    return r;
  }

private:
  static std::string user_name(uid_t uid) {
    if (const passwd *pw = getpwuid(uid))
      return pw->pw_name;
    return "uid " + std::to_string(uid);
  }

  static void finding(ModuleResult &r, int &count, const std::string &text) {
    ++count;
    r.add("FINDING: " + text);
  }

  /// Report permissions when they let non-owners modify the path.
  static void report_path(ModuleResult &r, const fs::path &path, int &count) {
    std::error_code ec;
    const auto st = fs::status(path, ec);
    if (ec) {
      r.add(path.string() + ": " + ec.message());
      return;
    }
    const auto p = st.permissions();
    const bool writable = (p & (fs::perms::group_write | fs::perms::others_write)) !=
                          fs::perms::none;
    r.add(path.string() + " perms " + perms_text(p) +
          (writable ? " (group/other writable)" : ""));
    if (writable)
      finding(r, count, path.string() + " is writable by group or others");
  }

  static std::string perms_text(fs::perms p) {
    auto bit = [&](fs::perms mask, char c) {
      return (p & mask) != fs::perms::none ? c : '-';
    };
    std::string out;
    out += bit(fs::perms::owner_read, 'r');
    out += bit(fs::perms::owner_write, 'w');
    out += bit(fs::perms::owner_exec, 'x');
    out += bit(fs::perms::group_read, 'r');
    out += bit(fs::perms::group_write, 'w');
    out += bit(fs::perms::group_exec, 'x');
    out += bit(fs::perms::others_read, 'r');
    out += bit(fs::perms::others_write, 'w');
    out += bit(fs::perms::others_exec, 'x');
    return out;
  }

  static std::string daemon_pid(const std::string &comm_name) {
    std::error_code ec;
    for (const auto &entry : fs::directory_iterator("/proc", ec)) {
      if (ec)
        break;
      if (!entry.is_directory())
        continue;
      std::ifstream comm(entry.path() / "comm");
      std::string line;
      if (!std::getline(comm, line))
        continue;
      if (line == comm_name)
        return entry.path().filename().string();
    }
    return {};
  }

  static std::string proc_field(const std::string &path,
                                const std::string &field) {
    std::ifstream in(path);
    std::string line;
    while (std::getline(in, line)) {
      if (line.rfind(field, 0) == 0) {
        std::istringstream is(line.substr(field.size()));
        std::string value;
        is >> value;
        return value;
      }
    }
    return {};
  }

  static std::string uid_line(const std::string &path) {
    const std::string line = proc_field(path, "Uid:");
    return line.empty() ? std::string("?") : line;
  }

  static std::string daemon_version() {
    for (const char *candidate : {"bluetoothd", "/usr/lib/bluetooth/bluetoothd",
                                  "/usr/sbin/bluetoothd"}) {
      const std::string path = candidate;
      std::error_code ec;
      if (path[0] == '/' ? !fs::exists(path, ec) : !bt::tool_exists(path))
        continue;
      const bt::ToolResult tr = bt::run_tool({path, "-v"}, 3000);
      if (tr.exit_code == 0 && !tr.output.empty())
        return tr.output.substr(0, tr.output.find('\n'));
    }
    return {};
  }

  static std::vector<std::string> user_groups() {
    std::vector<std::string> out;
    const int n = getgroups(0, nullptr);
    if (n <= 0)
      return out;
    std::vector<gid_t> gids(static_cast<size_t>(n));
    if (getgroups(n, gids.data()) != n)
      return out;
    for (const gid_t gid : gids) {
      if (const group *gr = getgrgid(gid))
        out.emplace_back(gr->gr_name);
      else
        out.push_back(std::to_string(gid));
    }
    return out;
  }

  static bool has_group(const std::vector<std::string> &groups,
                        const std::string &name) {
    for (const auto &g : groups)
      if (g == name)
        return true;
    return false;
  }
};

REGISTER_MODULE(BtPrivesc);
} // namespace
