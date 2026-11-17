#include "core/framework.h"
#include "core/advisories.h"
#include "core/bluez_dbus.h"
#include "core/bt.h"
#include "core/lab.h"
#include "core/logger.h"
#include "core/version.h"

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <getopt.h>
#include <iostream>
#include <sstream>
#include <unistd.h>

namespace blueboy {

namespace {

enum ExitCode {
  kOk = 0,
  kUsage = 1,
  kModuleFailed = 2,
  kScopeDenied = 3,
  kConsentRequired = 4,
  kLabDenied = 5,
};

const char *kBanner =
    R"(
    ____  __           ____
   / __ )/ /_  _____  / __ )____  __  __
  / __  / / / / / _ \/ __  / __ \/ / / /
 / /_/ / / /_/ /  __/ /_/ / /_/ / /_/ /
/_____/_/\__,_/\___/_____/\____/\__, /
                               /____/
)";

std::string resolve_config(const std::string &explicit_path) {
  if (!explicit_path.empty())
    return explicit_path;
  if (const char *env = std::getenv("BLUEBOY_CONFIG"); env && *env)
    return env;
  if (std::filesystem::exists("config/default.conf"))
    return "config/default.conf";
  return "/usr/share/blueboy/default.conf";
}

void print_section(const std::string &title) {
  std::cout << "\n[+] " << title << "\n\n";
}

} // namespace

void Framework::print_banner() const {
  if (no_banner_ || quiet_)
    return;
  std::cout << kBanner;
  std::cout << "    Bluetooth Security Assessment Framework v" << kVersion
            << "\n";
  std::cout
      << "    Read-only audits by default - offensive pack behind --lab\n\n";
}

void Framework::print_disclaimer() const {
  std::cout
      << "  Default modules are read-only: discovery, service enumeration and\n"
      << "  local adapter review. The offensive pack (floods, connect storms,\n"
      << "  AT command access, HID injection, link-key tests) is disabled "
         "unless\n"
      << "  you pass --lab. Nothing else is required, but scope enforcement "
         "stays\n"
      << "  active when configured.\n\n"
      << "  Offensive modules can crash controllers, drop links and alter "
         "peer\n"
      << "  state. Running them against hardware you do not own or administer "
         "is\n"
      << "  unlawful in most jurisdictions. You must hold prior written\n"
      << "  authorisation for every device you assess, accept full liability "
         "for\n"
      << "  the impact, and respect the agreed rules of engagement. The "
         "authors\n"
      << "  accept no responsibility for misuse or damage.\n\n";
}

void Framework::print_usage() const {
  std::cout << R"(Usage: blueboy [options]

Discovery:
  -s, --scan                  Discover BR/EDR devices
      --le-scan               Discover BLE advertisers
  -m, --module <name>         Run a module
      --category <name>       Run every module in a category
  -t, --target <BD_ADDR>      Target device address

Targets:
  -L, --targets <file>        Run the module against every address in a file
      --exclude <pattern>     Skip matching targets (glob, repeatable)
      --scope-check <BD_ADDR> Check one address against the allowlist and exit

Environment:
  -i, --interface <hciX>      Local adapter (default: hci0)
      --config <path>         Configuration file
  -o, --output <dir>          Report directory (default: output)
      --scope <path>          Allowlist file, enforced when [scope] enforce=1
      --lab                   Enable the offensive modules (prompts once)
      --dry-run               Show what would run, send nothing
      --check-config          Validate config, allowlist and registry, then exit
      --accept-terms          Record consent without prompting
      --show-consent          Show the stored consent token
      --revoke-consent        Delete the stored consent token
      --interactive           Shell for repeated runs
  -l, --list-modules          List modules
  -c, --list-categories       List categories
  -q, --quiet                 No banner, warnings and errors only
      --no-banner             Suppress the banner only
  -v, --verbose               Verbose output
  -d, --debug                 Debug output
  -h, --help                  Show this help
      --version               Show version

Examples:
  blueboy -s
  blueboy --le-scan -i hci0
  blueboy -m sdp_enum -t AA:BB:CC:DD:EE:FF
  blueboy --category hardening
  blueboy --lab -m l2cap_flood -t AA:BB:CC:DD:EE:FF
  blueboy --dry-run -m sdp_enum -t AA:BB:CC:DD:EE:FF
  blueboy -m service_audit -L hosts.txt --exclude 'AA:BB:*'
  blueboy --scope-check AA:BB:CC:DD:EE:FF
)";
}

void Framework::list_modules() const {
  auto mods = ModuleRegistry::instance().all();
  print_section(std::to_string(mods.size()) + " module(s)");
  for (auto *m : mods) {
    std::cout << "  * " << m->name() << "  [" << m->category() << "]"
              << (m->offensive() ? "  (offensive: needs --lab)" : "") << "\n"
              << "      " << m->description() << "\n"
              << "      Reference: " << m->cve()
              << " | Requires: " << m->requirements() << "\n";
    if (m->offensive())
      std::cout << "      Impact: " << m->impact() << "\n";
    std::cout << "\n";
  }
}

void Framework::list_categories() const {
  auto cats = ModuleRegistry::instance().categories();
  print_section(std::to_string(cats.size()) + " category(ies)");
  for (const auto &c : cats) {
    auto mods = ModuleRegistry::instance().by_category(c);
    std::cout << "  * " << c << " (" << mods.size() << " modules)\n";
    for (auto *m : mods)
      std::cout << "      - " << m->name() << "\n";
  }
  std::cout << "\n";
}

void Framework::emit_result(Module *m, const ModuleResult &r) {
  std::cout << "\n=== [" << m->name() << "] " << (r.success ? "OK" : "FAILED")
            << " ===\n";
  std::cout << r.summary << "\n";
  if (!r.details.empty()) {
    std::cout << "\n  Observations:\n";
    for (const auto &d : r.details)
      std::cout << "    - " << d << "\n";
  }
  if (!r.recommendations.empty()) {
    std::cout << "\n  Recommendations:\n";
    for (const auto &a : r.recommendations)
      std::cout << "    - " << a << "\n";
  }
  std::cout << "\n";
}

void Framework::record(Module *m, const ModuleContext &ctx,
                       const ModuleResult &r) {
  ReportEntry e;
  e.module = m->name();
  e.category = m->category();
  e.cve = m->cve();
  e.target = ctx.target;
  e.summary = r.summary;
  e.success = r.success;
  e.details = r.details;
  e.recommendations = r.recommendations;
  e.timestamp = timestamp_compact();

  if (writer_.write_module(e))
    session_.push_back(std::move(e));
  else
    LOG_WARN("Could not write report for " << m->name());
}

int Framework::do_scan() {
  if (!bt::iface_exists(iface_)) {
    LOG_ERROR("Adapter not found: " << iface_);
    return kUsage;
  }

  bt::InquiryOptions opt;
  opt.seconds = config_.get_int("scan", "inquiry_seconds", 10);
  opt.max_devices = config_.get_int("scan", "max_devices", 64);

  LOG_INFO("BR/EDR inquiry on " << iface_ << " for " << opt.seconds
                                << "s (bounded, passive listening)");

  std::string err;
  auto devices = bt::inquiry(iface_, opt, err);

  std::cout << "\n[+] Found " << devices.size() << " device(s):\n\n";
  for (const auto &d : devices) {
    std::cout << "  " << d.address << "  "
              << (d.name.empty() ? "(unknown)" : d.name) << "\n";
  }
  if (!err.empty())
    std::cout << "\n    note: " << err << "\n";
  std::cout << "\n";

  audit_log("scan.br_edr", iface_ + " found=" + std::to_string(devices.size()));
  return kOk;
}

int Framework::run_module(const std::string &name, const std::string &target) {
  Module *m = ModuleRegistry::instance().get(name);
  if (!m) {
    LOG_ERROR("Unknown module: " << name);
    return kUsage;
  }

  ModuleContext ctx;
  ctx.iface = iface_;
  ctx.output_dir = output_dir_;
  ctx.verbose = verbose_;
  ctx.debug = debug_;
  ctx.config = &config_;

  if (m->needs_target()) {
    if (target.empty()) {
      LOG_ERROR("Module '" << name << "' requires -t <BD_ADDR>");
      return kUsage;
    }
    ctx.target = bt::normalize_addr(target);
    if (!bt::is_valid_addr(ctx.target)) {
      LOG_ERROR("Invalid BD_ADDR: " << target
                                    << " (expected AA:BB:CC:DD:EE:FF)");
      return kUsage;
    }
    if (!target_allowed(ctx.target))
      return kScopeDenied;
  }

  if (dry_run_) {
    std::cout << "[dry-run] " << m->name() << " [" << m->category() << "]";
    if (!ctx.target.empty())
      std::cout << " -> " << ctx.target;
    if (m->offensive()) {
      const bool in_scope = !scope_enforced_ || scope_.allows(ctx.target);
      const LabDecision d = evaluate_lab(lab_, in_scope);
      std::cout << " | offensive "
                << (d == LabDecision::Allowed
                        ? "(gate satisfied)"
                        : "(blocked: " + lab_denial_reason(d) + ")");
    }
    if (m->needs_target() && !scope_enforced_)
      std::cout << " | scope enforcement off";
    std::cout << "\n";
    if (m->offensive())
      std::cout << "    impact: " << m->impact() << "\n";
    audit_log("module.plan", m->name() + " " + ctx.target);
    return kOk;
  }

  if (m->offensive() && !offensive_gate(m, ctx.target))
    return kLabDenied;

  LOG_INFO("Running module '"
           << m->name() << "'"
           << (ctx.target.empty() ? "" : " against " + ctx.target));
  audit_log("module.run",
            m->name() + " " + (ctx.target.empty() ? "(local)" : ctx.target));

  ModuleResult r = m->run(ctx);
  emit_result(m, r);
  record(m, ctx, r);
  return r.success ? kOk : kModuleFailed;
}

int Framework::run_category(const std::string &cat, const std::string &target) {
  auto mods = ModuleRegistry::instance().by_category(cat);
  if (mods.empty()) {
    LOG_ERROR("Unknown category: " << cat);
    return kUsage;
  }

  // Fail once, before any radio work, instead of repeating the same denial for
  // every offensive module in the category.
  if (!lab_) {
    for (auto *m : mods) {
      if (m->offensive()) {
        LOG_ERROR("Category '" << cat
                               << "' contains offensive modules. Re-run with "
                                  "--lab.");
        audit_log("offensive.denied", "category=" + cat + " reason=no-lab");
        return kLabDenied;
      }
    }
  }

  int rc = kOk;
  for (auto *m : mods) {
    const int r = run_module(m->name(), m->needs_target() ? target : "");
    if (r != kOk)
      rc = (r == kScopeDenied) ? kScopeDenied : kModuleFailed;
  }
  return rc;
}

bool Framework::target_allowed(const std::string &target) {
  for (const auto &pattern : excludes_) {
    if (Scope::glob_match(pattern, target)) {
      LOG_INFO("Target " << target << " matches --exclude '" << pattern
                         << "', skipping");
      audit_log("scope.excluded", target + " pattern=" + pattern);
      return false;
    }
  }

  if (!scope_enforced_)
    return true;

  if (scope_.allows(target)) {
    audit_log("scope.allowed", target);
    return true;
  }

  LOG_ERROR("Target " << target
                      << " is outside the authorised scope allowlist");
  LOG_ERROR(
      "Add it to the scope file only if the rules of engagement cover it");
  audit_log("scope.denied", target);
  return false;
}

int Framework::check_config() const {
  std::cout << "[+] Config: "
            << (config_path_.empty() ? "(built-in defaults)" : config_path_)
            << "\n"
            << "    interface   : " << iface_ << "\n"
            << "    output_dir  : " << output_dir_ << "\n"
            << "    modules     : " << ModuleRegistry::instance().all().size()
            << "\n"
            << "    bluez dbus  : "
            << (bluedbus::available() ? "available (sd-bus)"
                                      : "unavailable")
            << "\n";

  const std::string db = config_.get("advisories", "file",
                                     "config/advisories.conf");
  std::string db_err;
  const auto advisories = load_advisories(db, db_err);
  std::cout << "    advisories  : " << advisories.size() << " entr"
            << (advisories.size() == 1 ? "y" : "ies") << " from " << db
            << "\n";
  if (!db_err.empty())
    std::cout << "    [!] " << db_err << "\n";

  if (!scope_enforced_) {
    std::cout << "    scope       : not enforced (allowlist ignored)\n"
              << "[+] Config OK\n";
    return kOk;
  }

  std::cout << "    scope       : enforced, " << scope_.patterns().size()
            << " pattern(s)\n";
  if (scope_.patterns().empty()) {
    std::cout << "[!] Allowlist is empty: every target would be denied\n";
    return kUsage;
  }
  std::cout << "[+] Config OK\n";
  return kOk;
}

int Framework::check_scope(const std::string &target) const {
  const std::string addr = bt::normalize_addr(target);
  if (!bt::is_valid_addr(addr)) {
    LOG_ERROR("Invalid BD_ADDR: " << target << " (expected AA:BB:CC:DD:EE:FF)");
    return kUsage;
  }

  for (const auto &pattern : excludes_)
    if (Scope::glob_match(pattern, addr)) {
      std::cout << "[-] " << addr << " is excluded by --exclude '" << pattern
                << "'\n";
      return kScopeDenied;
    }

  if (!scope_enforced_) {
    std::cout << "[!] Scope is not enforced, so " << addr
              << " would be allowed. Enable [scope] enforce for a real check.\n";
    return kOk;
  }

  if (scope_.allows(addr)) {
    std::cout << "[+] " << addr << " is inside the authorised scope\n";
    return kOk;
  }

  std::cout << "[-] " << addr << " is OUTSIDE the authorised scope\n";
  return kScopeDenied;
}

std::vector<std::string> Framework::load_targets(const std::string &path) const {
  std::vector<std::string> out;
  std::ifstream in(path);
  if (!in) {
    LOG_ERROR("Cannot read target file: " << path);
    return out;
  }

  std::string line;
  int lineno = 0;
  while (std::getline(in, line)) {
    ++lineno;
    const auto start = line.find_first_not_of(" \t\r");
    if (start == std::string::npos)
      continue;
    line = line.substr(start);
    if (line[0] == '#')
      continue;
    const std::string addr = bt::normalize_addr(line);
    if (!bt::is_valid_addr(addr)) {
      LOG_WARN("Skipping invalid address on line " << lineno << ": " << line);
      continue;
    }
    out.push_back(addr);
  }
  return out;
}

int Framework::run_targets(const std::string &module,
                           const std::string &category,
                           const std::vector<std::string> &targets) {
  // In a batch, a target that is excluded or outside the allowlist is skipped
  // with a warning instead of aborting the whole run: one stale entry in a
  // fleet list must not hide the other results.
  std::vector<std::string> runnable;
  for (const auto &target : targets) {
    bool skipped = false;
    for (const auto &pattern : excludes_)
      if (Scope::glob_match(pattern, target)) {
        LOG_WARN("Skipping " << target << " (--exclude '" << pattern << "')");
        audit_log("scope.excluded", target + " pattern=" + pattern);
        skipped = true;
      }
    if (!skipped && scope_enforced_ && !scope_.allows(target)) {
      LOG_WARN("Skipping " << target << " (outside the allowlist)");
      audit_log("scope.skipped", target);
      skipped = true;
    }
    if (!skipped)
      runnable.push_back(target);
  }

  if (runnable.empty()) {
    LOG_ERROR("Every target was skipped (excluded or out of scope)");
    return kScopeDenied;
  }

  int rc = kOk;
  size_t index = 0;
  for (const auto &target : runnable) {
    ++index;
    if (!quiet_)
      std::cout << "\n[+] Target " << index << "/" << runnable.size() << ": "
                << target << "\n";
    const int r = !module.empty() ? run_module(module, target)
                                  : run_category(category, target);
    if (r != kOk && rc == kOk)
      rc = r;
  }
  return rc;
}

bool Framework::offensive_gate(Module *m, const std::string &target) {
  const bool in_scope = !scope_enforced_ || scope_.allows(target);
  const LabDecision decision = evaluate_lab(lab_, in_scope);

  if (decision != LabDecision::Allowed) {
    LOG_ERROR("'" << m->name() << "' is an offensive module. "
                  << lab_denial_reason(decision));
    audit_log("offensive.denied",
              m->name() + " " + target +
                  " reason=" + std::to_string(static_cast<int>(decision)));
    return false;
  }

  std::cout << "\n[!] OFFENSIVE MODULE: " << m->name() << "\n"
            << "    Target : " << target << "\n"
            << "    Impact : " << m->impact() << "\n"
            << "    The authors accept no liability for damage or misuse.\n\n";

  // One keystroke, only when a human is actually watching. With --lab and no
  // terminal the flag itself is the acknowledgement (scripts, CI, lab rigs).
  if (isatty(STDIN_FILENO) && !offensive_ack_) {
    std::cout << "Proceed? [y/N] " << std::flush;
    std::string answer;
    if (!std::getline(std::cin, answer))
      return false;
    if (answer.empty() || (answer[0] != 'y' && answer[0] != 'Y')) {
      std::cout << "Aborted. Nothing was sent.\n";
      audit_log("offensive.denied", m->name() + " " + target +
                                        " reason=operator-declined");
      return false;
    }
    offensive_ack_ = true;
  }

  audit_log("offensive.run", m->name() + " " + target);
  return true;
}

bool Framework::ensure_consent(bool accept_flag) {
  std::string detail;
  if (consent_recorded(&detail)) {
    LOG_DEBUG("Consent token found: " << detail);
    return true;
  }

  if (accept_flag) {
    std::string err;
    if (!write_consent(err)) {
      LOG_ERROR(err);
      return false;
    }
    audit_log("consent.record", "non-interactive via --accept-terms");
    LOG_INFO("Consent recorded in " << consent_token_path());
    return true;
  }

  print_disclaimer();

  if (!isatty(STDIN_FILENO)) {
    LOG_ERROR("No consent token and no terminal to prompt on.");
    LOG_ERROR("Re-run with --accept-terms once you have read the disclaimer.");
    return false;
  }

  std::cout << "Type 'I ACCEPT' to record consent in " << consent_token_path()
            << ", or 'no' to abort: " << std::flush;

  std::string answer;
  if (!std::getline(std::cin, answer))
    return false;

  if (answer != "I ACCEPT") {
    std::cout << "Consent not recorded. No radio operation was performed.\n";
    return false;
  }

  std::string err;
  if (!write_consent(err)) {
    LOG_ERROR(err);
    return false;
  }
  audit_log("consent.record", "interactive acknowledgement");
  std::cout << "[+] Consent recorded. Thank you.\n\n";
  return true;
}

bool Framework::bootstrap_environment(const std::string &cfg_path) {
  if (debug_)
    Logger::instance().set_level(LogLevel::DEBUG);
  else if (verbose_)
    Logger::instance().set_level(LogLevel::TRACE);
  else if (quiet_)
    Logger::instance().set_level(LogLevel::WARN);

  std::error_code ec;
  std::filesystem::create_directories("logs", ec);
  Logger::instance().set_file("logs/blueboy.log");

  if (config_.load(cfg_path)) {
    config_path_ = cfg_path;
    LOG_DEBUG("Configuration loaded: " << cfg_path);
    // Command-line choices must survive the config load, otherwise -i/-o look
    // like they work and reports silently land somewhere else.
    if (!iface_set_)
      iface_ = config_.get("general", "interface", iface_);
    if (!output_set_)
      output_dir_ = config_.get("general", "output_dir", output_dir_);
  } else {
    LOG_WARN("Config not found (" << cfg_path << "), using defaults");
  }

  writer_ = ReportWriter(output_dir_);
  return true;
}

int Framework::interactive() {
  std::cout << "Interactive mode. Type 'help' for commands, 'exit' to leave.\n";
  std::string line;

  while (true) {
    std::cout << "blueboy> " << std::flush;
    if (!std::getline(std::cin, line))
      break;

    std::istringstream is(line);
    std::string cmd, a1, a2;
    is >> cmd >> a1 >> a2;

    if (cmd.empty())
      continue;
    if (cmd == "exit" || cmd == "quit")
      break;
    if (cmd == "help") {
      std::cout << "  list | categories | scan | lescan\n"
                << "  run <module> <target> | category <cat> <target>\n"
                << "  consent | exit\n";
    } else if (cmd == "list") {
      list_modules();
    } else if (cmd == "categories") {
      list_categories();
    } else if (cmd == "scan") {
      do_scan();
    } else if (cmd == "lescan") {
      std::string err;
      bt::LeScanOptions opt;
      opt.seconds = config_.get_int("scan", "le_seconds", 8);
      auto devices = bt::le_scan(iface_, opt, err);
      for (const auto &d : devices)
        std::cout << "  " << d.address << "  " << d.name << "\n";
      if (!err.empty())
        std::cout << "  note: " << err << "\n";
    } else if (cmd == "run") {
      run_module(a1, a2);
    } else if (cmd == "category") {
      run_category(a1, a2);
    } else if (cmd == "consent") {
      std::string detail;
      if (consent_recorded(&detail))
        std::cout << "  stored: " << detail << "\n";
      else
        std::cout << "  no consent token on this host\n";
    } else {
      std::cout << "Unknown command '" << cmd << "'.\n";
    }
  }
  return kOk;
}

int Framework::run(int argc, char **argv) {
  static const option long_opts[] = {
      {"help", no_argument, nullptr, 'h'},
      {"version", no_argument, nullptr, 1007},
      {"list-modules", no_argument, nullptr, 'l'},
      {"list-categories", no_argument, nullptr, 'c'},
      {"interactive", no_argument, nullptr, 1006},
      {"module", required_argument, nullptr, 'm'},
      {"target", required_argument, nullptr, 't'},
      {"category", required_argument, nullptr, 1000},
      {"config", required_argument, nullptr, 1001},
      {"interface", required_argument, nullptr, 'i'},
      {"output", required_argument, nullptr, 'o'},
      {"scope", required_argument, nullptr, 1002},
      {"lab", no_argument, nullptr, 1009},
      {"accept-terms", no_argument, nullptr, 1003},
      {"show-consent", no_argument, nullptr, 1004},
      {"revoke-consent", no_argument, nullptr, 1005},
      {"scan", no_argument, nullptr, 's'},
      {"le-scan", no_argument, nullptr, 1008},
      {"quiet", no_argument, nullptr, 'q'},
      {"no-banner", no_argument, nullptr, 1011},
      {"dry-run", no_argument, nullptr, 1012},
      {"check-config", no_argument, nullptr, 1013},
      {"scope-check", required_argument, nullptr, 1014},
      {"targets", required_argument, nullptr, 'L'},
      {"exclude", required_argument, nullptr, 1015},
      {"verbose", no_argument, nullptr, 'v'},
      {"debug", no_argument, nullptr, 'd'},
      {nullptr, 0, nullptr, 0}};

  std::string cfg_path;
  std::string scope_path;
  std::string module;
  std::string target;
  std::string category;
  std::string targets_file;
  std::string scope_check;
  bool check_cfg = false;
  bool scan = false;
  bool le_scan = false;
  bool interactive_mode = false;
  bool accept_terms = false;
  bool show_consent = false;
  bool revoke = false;

  int c;
  while ((c = getopt_long(argc, argv, "hlcsm:t:i:o:L:qvd", long_opts,
                          nullptr)) != -1) {
    switch (c) {
    case 'h':
      print_banner();
      print_usage();
      return kOk;
    case 1007:
      std::cout << kToolName << " " << kVersion << "\n";
      return kOk;
    case 'l':
      list_modules();
      return kOk;
    case 'c':
      list_categories();
      return kOk;
    case 1006:
      interactive_mode = true;
      break;
    case 'm':
      module = optarg;
      break;
    case 't':
      target = optarg;
      break;
    case 'i':
      iface_ = optarg;
      iface_set_ = true;
      break;
    case 'o':
      output_dir_ = optarg;
      output_set_ = true;
      break;
    case 's':
      scan = true;
      break;
    case 1008:
      le_scan = true;
      break;
    case 'q':
      quiet_ = true;
      break;
    case 1011:
      no_banner_ = true;
      break;
    case 1012:
      dry_run_ = true;
      break;
    case 1013:
      check_cfg = true;
      break;
    case 1014:
      scope_check = optarg;
      break;
    case 'L':
      targets_file = optarg;
      break;
    case 1015:
      excludes_.emplace_back(optarg);
      break;
    case 'v':
      verbose_ = true;
      break;
    case 'd':
      debug_ = true;
      break;
    case 1000:
      category = optarg;
      break;
    case 1001:
      cfg_path = optarg;
      break;
    case 1002:
      scope_path = optarg;
      break;
    case 1009:
      lab_ = true;
      break;
    case 1003:
      accept_terms = true;
      break;
    case 1004:
      show_consent = true;
      break;
    case 1005:
      revoke = true;
      break;
    default:
      print_usage();
      return kUsage;
    }
  }

  print_banner();

  if (revoke) {
    if (revoke_consent()) {
      audit_log("consent.revoke", "token removed by operator");
      std::cout << "[+] Consent token removed.\n";
      return kOk;
    }
    std::cout << "[!] No consent token to remove.\n";
    return kOk;
  }

  if (show_consent) {
    std::string detail;
    if (consent_recorded(&detail))
      std::cout << "[+] " << consent_token_path() << "\n    " << detail << "\n";
    else
      std::cout << "[!] No consent token recorded on this host.\n";
    return kOk;
  }

  // An explicit --config that cannot be read must not silently fall back to
  // defaults: that would drop the scope allowlist without telling the operator.
  const std::string cfg = resolve_config(cfg_path);
  if (!cfg_path.empty() && !std::filesystem::exists(cfg)) {
    LOG_ERROR("Config not found: " << cfg);
    LOG_ERROR("Refusing to run with defaults after an explicit --config");
    return kUsage;
  }
  bootstrap_environment(cfg);

  scope_enforced_ = config_.get_bool("scope", "enforce", false);
  if (scope_enforced_) {
    const std::string file = scope_path.empty()
                                 ? config_.get("scope", "allowlist_file", "")
                                 : scope_path;
    if (file.empty()) {
      LOG_ERROR("[scope] enforce is on but no allowlist_file is configured");
      return kScopeDenied;
    }
    std::string err;
    if (!scope_.load_file(file, err)) {
      LOG_ERROR("Scope is enforced and cannot be loaded: " << err);
      LOG_ERROR(
          "Refusing to run. Fix the allowlist or disable [scope] enforce");
      return kScopeDenied;
    }
    LOG_INFO("Scope enforcement active (" << scope_.patterns().size()
                                          << " pattern(s), source: " << file
                                          << ")");
  } else if (!scope_path.empty()) {
    LOG_WARN("--scope supplied but [scope] enforce is off in the config");
  }

  // Offline or planning modes: no consent needed, nothing touches radio.
  if (check_cfg)
    return check_config();
  if (!scope_check.empty())
    return check_scope(scope_check);

  if (!targets_file.empty() && module.empty() && category.empty()) {
    LOG_ERROR("-L/--targets needs -m <module> or --category <name>");
    return kUsage;
  }

  std::vector<std::string> targets;
  if (!targets_file.empty()) {
    targets = load_targets(targets_file);
    if (targets.empty()) {
      LOG_ERROR("No usable target in " << targets_file);
      return kUsage;
    }
    if (!target.empty())
      LOG_WARN("-t is ignored because -L was supplied (" << targets.size()
                                                         << " target(s))");
  }

  // Everything below touches radio hardware or third-party devices.
  if (!dry_run_ && (scan || le_scan || interactive_mode || !module.empty() ||
                    !category.empty())) {
    if (!ensure_consent(accept_terms))
      return kConsentRequired;
  }

  LOG_INFO("Loaded " << ModuleRegistry::instance().all().size()
                     << " module(s)");
  audit_log("session.start",
            "iface=" + iface_ + " output=" + output_dir_ +
                (module.empty() ? "" : " module=" + module) +
                (category.empty() ? "" : " category=" + category));

  int rc = kOk;
  if (scan) {
    if (dry_run_) {
      std::cout << "[dry-run] BR/EDR inquiry on " << iface_ << " for "
                << config_.get_int("scan", "inquiry_seconds", 10) << "s\n";
      return kOk;
    }
    rc = do_scan();
  } else if (le_scan) {
    if (dry_run_) {
      std::cout << "[dry-run] BLE advertising scan on " << iface_ << " for "
                << config_.get_int("scan", "le_seconds", 8) << "s\n";
      return kOk;
    }
    bt::LeScanOptions opt;
    opt.seconds = config_.get_int("scan", "le_seconds", 8);
    opt.max_devices = config_.get_int("scan", "max_devices", 64);
    std::string err;
    auto devices = bt::le_scan(iface_, opt, err);
    std::cout << "\n[+] Found " << devices.size() << " BLE advertiser(s):\n\n";
    for (const auto &d : devices) {
      std::cout << "  " << d.address << "  " << d.name << "  (RSSI "
                << static_cast<int>(d.rssi) << ")\n";
    }
    std::cout << "\n";
    if (!err.empty())
      std::cout << "    note: " << err << "\n\n";
    audit_log("scan.le", iface_ + " found=" + std::to_string(devices.size()));
    rc = err.empty() ? kOk : kModuleFailed;
  } else if (!module.empty()) {
    rc = targets.empty() ? run_module(module, target)
                         : run_targets(module, "", targets);
  } else if (!category.empty()) {
    rc = targets.empty() ? run_category(category, target)
                         : run_targets("", category, targets);
  } else if (interactive_mode)
    rc = interactive();
  else
    print_usage();

  if (!session_.empty() && writer_.write_session(session_, iface_))
    std::cout << "[+] Session report: " << writer_.session_path() << "\n";

  audit_log("session.end", "rc=" + std::to_string(rc));
  return rc;
}

} // namespace blueboy
