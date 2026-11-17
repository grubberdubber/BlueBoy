#include "core/bt.h"
#include "core/config.h"
#include "core/module.h"

#include <filesystem>
#include <sstream>

namespace {
using namespace blueboy;

/// Bluecrack: recover a legacy pairing PIN from a captured pairing exchange.
/// The module drives the established tools (crackle / btcrack) instead of
/// reimplementing the crypto, so the operator can audit every step.
class Bluecrack : public Module {
public:
  std::string name() const override { return "bluecrack"; }
  std::string category() const override { return "offensive"; }
  std::string description() const override {
    return "Legacy PIN recovery from a pairing capture (crackle / btcrack)";
  }
  std::string cve() const override { return "CVE-2018-5383 (context)"; }
  std::string requirements() const override {
    return "crackle or btcrack, a pairing pcap, lab authorisation";
  }
  bool offensive() const override { return true; }
  std::string impact() const override {
    return "Recovers a legacy PIN or link key from a capture. A recovered key "
           "allows impersonation, so treat the output as a secret.";
  }

  ModuleResult run(const ModuleContext &ctx) override {
    ModuleResult r;

    const std::string capture = ctx.config->get("bluecrack", "capture", "");
    if (capture.empty()) {
      r.summary = "No pairing capture configured";
      r.add("Set [bluecrack] capture = /path/to/pairing.pcap");
      r.advise("Capture the pairing exchange with 'btmon -w pairing.log' or "
               "hcidump, then convert it to pcap for crackle");
      r.advise("Legacy PINs are 4 digits by default: recovery is usually a "
               "matter of minutes, which is why SSP must be enforced");
      return r;
    }

    std::error_code ec;
    if (!std::filesystem::exists(capture, ec) || ec) {
      r.summary = "Capture not found: " + capture;
      r.advise("Verify the path; the file must be readable by the operator");
      return r;
    }

    std::error_code dir_ec;
    std::filesystem::create_directories(ctx.output_dir, dir_ec);

    std::string tool;
    std::vector<std::string> argv;
    if (bt::tool_exists("crackle")) {
      tool = "crackle";
      argv = {"crackle", "-i", capture, "-o",
              (std::filesystem::path(ctx.output_dir) / "crackle.pcap").string()};
    } else if (bt::tool_exists("btcrack")) {
      tool = "btcrack";
      argv = {"btcrack", "-f", capture};
      const std::string words = ctx.config->get("bluecrack", "wordlist", "");
      if (!words.empty())
        argv.insert(argv.end(), {"-w", words});
    } else {
      r.summary = "Neither crackle nor btcrack is installed";
      r.add("Install crackle (AUR/git) or btcrack to run the recovery");
      r.advise("Without a capture and a recovery tool the PIN cannot be "
               "recovered; there is no safe shortcut");
      return r;
    }

    bt::ToolResult tr =
        bt::run_tool(argv, ctx.config->get_int("bluecrack", "timeout_ms", 120000),
                     ctx.output_dir);

    r.add("Tool: " + tool + " (exit " + std::to_string(tr.exit_code) + ")");
    if (!tr.output.empty()) {
      std::string out = tr.output;
      if (out.size() > 800)
        out = out.substr(0, 800) + "\n...";
      r.add("Output:\n" + out);
    }

    r.success = tr.exit_code == 0;
    r.summary = r.success ? tool + " completed its analysis"
                          : tool + " did not complete";

    if (tr.exit_code == -2)
      r.add("The tool hit the time limit and was killed");
    if (!r.success && capture.find(".log") != std::string::npos)
      r.advise("Convert the btmon log to pcap first: crackle reads pcap, not "
               "btmon's text format");
    r.advise("Store any recovered PIN/key outside the report tree and delete it "
             "at the end of the engagement");
    r.advise("Force Secure Simple Pairing with Secure Connections and disable "
             "legacy PIN pairing on every device");
    return r;
  }
};

REGISTER_MODULE(Bluecrack);
} // namespace
