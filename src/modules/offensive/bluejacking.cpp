#include "core/bt.h"
#include "core/config.h"
#include "core/module.h"

#include <filesystem>
#include <fstream>
#include <sstream>

namespace {
using namespace blueboy;

/// Bluejacking: push an unsolicited vCard to the peer through OBEX Object Push.
/// The card is generated in the report directory so the content is auditable.
class Bluejacking : public Module {
public:
  std::string name() const override { return "bluejacking"; }
  std::string category() const override { return "offensive"; }
  std::string description() const override {
    return "OBEX Object Push of a vCard (unsolicited message test)";
  }
  std::string requirements() const override {
    return "obexftp or ussp-push, Object Push profile, lab authorisation";
  }
  bool offensive() const override { return true; }
  std::string impact() const override {
    return "Delivers one unsolicited vCard to the peer. The user sees a contact "
           "prompt; nothing is stored unless they accept it.";
  }

  ModuleResult run(const ModuleContext &ctx) override {
    ModuleResult r;

    std::error_code ec;
    std::filesystem::create_directories(ctx.output_dir, ec);

    const std::string name = ctx.config->get("bluejacking", "contact_name",
                                             "BlueBoy Lab Test");
    const std::string number = ctx.config->get("bluejacking", "contact_number",
                                               "+10000000000");
    const auto card = std::filesystem::path(ctx.output_dir) / "bluejack.vcf";

    {
      std::ofstream out(card);
      if (!out) {
        r.summary = "Could not write " + card.string();
        r.advise("Check write permissions on the output directory");
        return r;
      }
      out << "BEGIN:VCARD\nVERSION:3.0\nFN:" << name << "\nTEL;TYPE=CELL:"
          << number << "\nNOTE:Authorised BlueBoy lab test\nEND:VCARD\n";
    }
    r.add("Generated card: " + card.string());

    if (bt::tool_exists("obexftp")) {
      bt::ToolResult tr = bt::run_tool(
          {"obexftp", "-b", ctx.target, "-p", card.string()},
          ctx.config->get_int("bluejacking", "timeout_ms", 20000));
      r.add("obexftp exit code " + std::to_string(tr.exit_code));
      r.success = tr.exit_code == 0;
      if (!tr.output.empty())
        r.add("Tool output: " + tr.output.substr(0, 200));
    } else if (bt::tool_exists("ussp-push")) {
      const int channel = ctx.config->get_int("bluejacking", "channel", 10);
      const std::string dest =
          ctx.target + "@" + std::to_string(channel);
      bt::ToolResult tr = bt::run_tool(
          {"ussp-push", dest, card.string(), "bluejack.vcf"},
          ctx.config->get_int("bluejacking", "timeout_ms", 20000));
      r.add("ussp-push exit code " + std::to_string(tr.exit_code));
      r.success = tr.exit_code == 0;
    } else {
      r.summary = "No OBEX push tool available";
      r.add("Install obexftp or ussp-push to deliver the card");
      r.advise("The generated vCard is kept for inspection even without a tool");
      return r;
    }

    r.summary = r.success
                    ? "vCard pushed to " + ctx.target + " through OBEX Object Push"
                    : "OBEX push was refused or failed";
    if (!r.success)
      r.advise("Object Push usually requires the peer to be in discoverable "
               "mode and to accept the transfer; a refusal is the expected "
               "secure behaviour");
    r.advise("Disable 'Receive files' / Object Push on devices that do not need it");
    return r;
  }
};

REGISTER_MODULE(Bluejacking);
} // namespace
