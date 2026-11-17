// Minimal dependency-free test runner: returns non-zero when any check fails.
#include "core/advisories.h"
#include "core/bluez_store.h"
#include "core/bt.h"
#include "core/config.h"
#include "core/lab.h"
#include "core/oui.h"
#include "core/report.h"
#include "core/roe.h"

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>

namespace {

int g_failures = 0;
int g_checks = 0;

void check(bool cond, const std::string &what) {
  ++g_checks;
  if (!cond) {
    ++g_failures;
    std::printf("FAIL: %s\n", what.c_str());
  }
}

std::string temp_file(const std::string &name, const std::string &body) {
  const auto path = std::filesystem::temp_directory_path() / name;
  std::ofstream f(path);
  f << body;
  return path.string();
}

void test_config() {
  const std::string path = temp_file(
      "blueboy_test.conf",
      "# comment\n"
      "[general]\n"
      "interface = hci1\n"
      "timeout = 12\n"
      "\n"
      "[scope]\n"
      "enforce = yes\n"
      "ratio = 0.75\n");

  blueboy::Config cfg;
  check(cfg.load(path), "config loads from disk");
  check(cfg.get("general", "interface") == "hci1", "string value parsed");
  check(cfg.get_int("general", "timeout", 0) == 12, "int value parsed");
  check(cfg.get_int("general", "missing", 7) == 7, "int default used");
  check(cfg.get_bool("scope", "enforce", false), "bool value parsed");
  check(cfg.get_bool("scope", "absent", true), "bool default used");
  check(cfg.get_double("scope", "ratio", 0.0) == 0.75, "double value parsed");

  blueboy::Config missing;
  check(!missing.load("/nonexistent/blueboy.conf"), "missing config rejected");
  check(missing.get("general", "interface", "hci0") == "hci0",
        "defaults apply without a config");

  std::filesystem::remove(path);
}

void test_scope() {
  using blueboy::Scope;

  check(Scope::glob_match("AA:BB:CC:DD:EE:FF", "aa:bb:cc:dd:ee:ff"),
        "scope match is case-insensitive");
  check(Scope::glob_match("AA:BB:CC:*", "AA:BB:CC:11:22:33"),
        "scope prefix wildcard matches");
  check(!Scope::glob_match("AA:BB:CC:*", "AA:BB:DD:11:22:33"),
        "scope prefix wildcard rejects other prefixes");
  check(Scope::glob_match("*", "AA:BB:CC:DD:EE:FF"), "scope star matches all");
  check(Scope::glob_match("AA:BB:CC:DD:EE:F?", "AA:BB:CC:DD:EE:FF"),
        "scope question mark matches one character");
  check(!Scope::glob_match("AA:BB:CC:DD:EE:FF", "AA:BB:CC:DD:EE"),
        "scope rejects shorter address");

  Scope scope;
  check(!scope.allows("AA:BB:CC:DD:EE:FF"), "empty scope denies by default");
  scope.add_pattern("AA:BB:CC:*");
  check(scope.allows("AA:BB:CC:DD:EE:FF"), "added pattern allows target");
  check(!scope.allows("11:22:33:44:55:66"), "unlisted target is denied");

  const std::string path =
      temp_file("blueboy_scope.conf",
                "# authorised lab\n"
                "AA:BB:CC:DD:EE:FF\n"
                "\n"
                "11:22:33:*\n");
  Scope loaded;
  std::string err;
  check(loaded.load_file(path, err), "scope file loads");
  check(loaded.patterns().size() == 2, "comments and blank lines skipped");
  check(loaded.allows("AA:BB:CC:DD:EE:FF"), "exact entry allowed");
  check(loaded.allows("11:22:33:AA:BB:CC"), "wildcard entry allowed");
  check(!loaded.allows("99:99:99:99:99:99"), "unknown entry denied");

  std::filesystem::remove(path);

  std::string load_err;
  Scope bad;
  check(!bad.load_file("/nonexistent/scope.conf", load_err),
        "missing scope file fails closed");
}

void test_json_escape() {
  using blueboy::ReportWriter;

  check(ReportWriter::json_escape("plain") == "plain", "plain text unchanged");
  check(ReportWriter::json_escape("a\"b") == "a\\\"b", "quote escaped");
  check(ReportWriter::json_escape("a\\b") == "a\\\\b", "backslash escaped");
  check(ReportWriter::json_escape("a\nb") == "a\\nb", "newline escaped");
  check(ReportWriter::json_escape("a\tb") == "a\\tb", "tab escaped");
  check(ReportWriter::json_escape(std::string("\x01")) == "\\u0001",
        "control byte escaped as unicode");
  check(ReportWriter::json_escape("ñandú") == "ñandú", "utf-8 preserved");
}

void test_address() {
  check(blueboy::bt::is_valid_addr("AA:BB:CC:DD:EE:FF"),
        "valid address accepted");
  check(!blueboy::bt::is_valid_addr("not-an-address"),
        "garbage address rejected");
  check(!blueboy::bt::is_valid_addr("AA:BB:CC:DD:EE"),
        "short address rejected");
  check(blueboy::bt::normalize_addr("aa:bb:cc:dd:ee:ff") ==
            "AA:BB:CC:DD:EE:FF",
        "address normalised");
}

void test_report_writer() {
  namespace fs = std::filesystem;
  const fs::path dir = fs::temp_directory_path() / "blueboy_test_reports";
  fs::remove_all(dir);

  blueboy::ReportWriter writer(dir.string());
  blueboy::ReportEntry entry;
  entry.module = "sdp_enum";
  entry.category = "reconnaissance";
  entry.target = "AA:BB:CC:DD:EE:FF";
  entry.summary = "found \"2\" records";
  entry.success = true;
  entry.details.push_back("line one");
  entry.recommendations.push_back("disable unused services");
  entry.timestamp = blueboy::timestamp_compact();

  check(writer.write_module(entry), "module report written");
  check(fs::exists(dir / ("sdp_enum_" + entry.timestamp + ".json")),
        "json report exists");

  std::ifstream js(dir / ("sdp_enum_" + entry.timestamp + ".json"));
  std::string body((std::istreambuf_iterator<char>(js)),
                   std::istreambuf_iterator<char>());
  check(body.find("\"summary\": \"found \\\"2\\\" records\"") !=
            std::string::npos,
        "summary is escaped in json output");

  check(writer.write_session({entry}, "hci0"), "session report written");
  check(fs::exists(writer.session_path()), "session file exists");

  fs::remove_all(dir);
}

void test_lab_gate() {
  using blueboy::LabDecision;
  using blueboy::evaluate_lab;

  check(evaluate_lab(true, true) == LabDecision::Allowed,
        "lab gate allows an in-scope target with --lab");
  check(evaluate_lab(false, true) == LabDecision::LabFlagMissing,
        "lab gate needs --lab");
  check(evaluate_lab(false, false) == LabDecision::LabFlagMissing,
        "missing --lab is reported before scope");
  check(evaluate_lab(true, false) == LabDecision::OutOfScope,
        "lab gate rejects out-of-scope targets");
  check(!blueboy::lab_denial_reason(LabDecision::LabFlagMissing).empty(),
        "denial reason explains the missing flag");
  check(!blueboy::lab_denial_reason(LabDecision::OutOfScope).empty(),
        "denial reason explains the allowlist");
}

void test_oui() {
  using namespace blueboy::oui;

  check(prefix_key("00-1A-7D") == "001A7D", "IEEE prefix normalised");
  check(prefix_key("00:1a:7d") == "001A7D", "colon prefix normalised");
  check(prefix_key("not-a-prefix").empty(), "garbage prefix rejected");

  std::string prefix, vendor;
  check(parse_oui_line("00-1A-7D   (hex)\t\tcyber-blue(HK)Ltd", prefix,
                       vendor) &&
            prefix == "001A7D" && vendor == "cyber-blue(HK)Ltd",
        "IEEE line parsed");
  check(parse_oui_line("001A7D cyber-blue(HK)Ltd", prefix, vendor) &&
            prefix == "001A7D" && vendor == "cyber-blue(HK)Ltd",
        "nmap line parsed");
  check(!parse_oui_line("OUI/MA-L  Organization", prefix, vendor),
        "header line ignored");
  check(!parse_oui_line("# comment", prefix, vendor), "comment ignored");

  const std::string path = temp_file(
      "blueboy_oui.txt",
      "OUI/MA-L    Organization\n"
      "00-1A-7D   (hex)\t\tcyber-blue(HK)Ltd\n"
      "001122 some-vendor\n");
  check(vendor_from_file(path, "00:1A:7D:11:22:33") == "cyber-blue(HK)Ltd",
        "vendor resolved from file");
  check(vendor_from_file(path, "00:11:22:33:44:55") == "some-vendor",
        "nmap entry resolved from file");
  check(vendor_from_file(path, "AA:BB:CC:DD:EE:FF").empty(),
        "unknown prefix returns empty");
  std::filesystem::remove(path);
}

void test_bluez_store() {
  using blueboy::bluez::Bond;

  Bond bond;
  check(blueboy::bluez::parse_settings_text("[General]\nName=Test Phone\n\n"
                                            "[LinkKey]\nKey=0A1B2C\nType=4\n",
                                            bond),
        "settings text parsed");
  check(bond.name == "Test Phone", "bond name parsed");
  check(bond.has_link_key, "link key presence detected");
  check(bond.key_type == "legacy PIN", "legacy key type labelled");

  Bond modern;
  check(blueboy::bluez::parse_settings_text("[LinkKey]\nKey=AA\nType=8\n", modern),
        "modern key parsed");
  check(modern.key_type == "Secure Connections", "SC key type labelled");

  Bond empty;
  check(!blueboy::bluez::parse_settings_text("# nothing here\n", empty),
        "unrelated text rejected");

  std::string err;
  const auto none = blueboy::bluez::read_bonds("/nonexistent/bluez", err);
  check(none.empty() && !err.empty(), "missing bond store reported");
}

void test_advisories() {
  using blueboy::Advisory;
  using blueboy::advisory_matches;
  using blueboy::load_advisories;
  using blueboy::severity_rank;

  const std::string path = temp_file(
      "blueboy_advisories.conf",
      "# test database\n"
      "[low_one]\n"
      "name = Low one\n"
      "cves = CVE-0000-0001\n"
      "class = info-leak\n"
      "severity = low\n"
      "match = any\n"
      "fixed = 1.0\n"
      "\n"
      "[fast_pair_one]\n"
      "name = Fast Pair one\n"
      "cves = CVE-2025-36911\n"
      "class = hijack\n"
      "severity = critical\n"
      "match = fast_pair\n"
      "vendors = Sony, JBL\n"
      "condition = advertised\n");

  std::string err;
  const auto advisories = load_advisories(path, err);
  check(advisories.size() == 2, "both advisories loaded");
  check(err.empty(), "clean database reports no error");
  check(!advisories.empty() && advisories.front().severity == "critical",
        "entries sorted by severity");
  check(severity_rank("critical") < severity_rank("low"),
        "severity ranking ordered");

  Advisory fast;
  for (const auto &a : advisories)
    if (a.key == "fast_pair_one")
      fast = a;
  check(fast.vendors.size() == 2, "vendor list split");

  check(advisory_matches(fast, true, true, true, true, "Sony Corporation"),
        "fast pair match with vendor");
  check(!advisory_matches(fast, true, true, true, true, "Earda Technologies"),
        "vendor filter rejects other vendors");
  check(!advisory_matches(fast, true, true, true, false, "Sony"),
        "fast pair surface missing");

  Advisory any;
  for (const auto &a : advisories)
    if (a.key == "low_one")
      any = a;
  check(advisory_matches(any, false, true, false, false, ""),
        "any-match needs one reachable surface");
  check(!advisory_matches(any, false, false, false, false, ""),
        "any-match fails without a surface");

  const std::string broken = temp_file(
      "blueboy_advisories_broken.conf",
      "[incomplete]\nseverity = high\n");
  std::string broken_err;
  const auto none = load_advisories(broken, broken_err);
  check(none.empty() && !broken_err.empty(), "incomplete entry reported");

  std::string missing_err;
  check(load_advisories("/nonexistent/advisories.conf", missing_err).empty() &&
            !missing_err.empty(),
        "missing database reported");

  std::filesystem::remove(path);
  std::filesystem::remove(broken);
}

} // namespace

int main() {
  test_config();
  test_scope();
  test_json_escape();
  test_address();
  test_report_writer();
  test_lab_gate();
  test_oui();
  test_bluez_store();
  test_advisories();

  std::printf("%d checks, %d failure(s)\n", g_checks, g_failures);
  return g_failures == 0 ? 0 : 1;
}
