#include "core/bt.h"
#include "core/config.h"
#include "core/module.h"
#include "hci_probe.h"

#include <filesystem>
#include <fstream>

namespace {
using namespace blueboy;

/// BlueDucky: HID keystroke injection needs the attacker to present itself as a
/// Bluetooth keyboard. BlueZ cannot switch a normal adapter into HID-device
/// mode, so the module verifies that the peer exposes HID and generates a
/// ready-to-run DuckyScript payload for an HID-capable rig.
class Blueducky : public Module {
public:
  std::string name() const override { return "blueducky"; }
  std::string category() const override { return "offensive"; }
  std::string description() const override {
    return "HID injection readiness: HID exposure check and DuckyScript payload";
  }
  std::string cve() const override { return "CVE-2023-45866 (context)"; }
  std::string requirements() const override {
    return "peer exposing HID (0x1124), an HID-capable injection rig";
  }
  bool offensive() const override { return true; }
  std::string impact() const override {
    return "Generates a keystroke payload and checks HID exposure. It does not "
           "pair or type on the peer from a standard adapter.";
  }

  ModuleResult run(const ModuleContext &ctx) override {
    ModuleResult r;

    std::string err;
    const auto services = bt::sdp_services(ctx.target, err);
    const bool hid = offensive::has_service(services, 0x1124) ||
                     offensive::has_service(services, 0x1812);

    r.add("SDP records: " + std::to_string(services.size()));
    r.add(std::string("HID service (0x1124 / 0x1812): ") +
          (hid ? "advertised" : "not advertised"));

    std::error_code ec;
    std::filesystem::create_directories(ctx.output_dir, ec);
    const auto payload = std::filesystem::path(ctx.output_dir) / "ducky.txt";

    {
      std::ofstream out(payload);
      if (!out) {
        r.summary = "Could not write " + payload.string();
        return r;
      }
      out << "REM Authorised BlueBoy HID injection test\n"
          << "REM Verify the target window before running this payload\n"
          << "DELAY 1500\n"
          << "STRING echo blueboy-hid-test\n"
          << "ENTER\n";
    }

    r.success = hid;
    r.summary = hid ? "Peer exposes HID; payload written to " + payload.string()
                    : "Peer does not advertise HID";

    r.add("Payload: " + payload.string());
    r.add("Injection requires a controller or dongle that can present a HID "
          "device; BlueZ hosts cannot do it with a stock adapter");

    if (hid) {
      r.advise("Use a dedicated HID-capable rig and pair it in the lab, never on "
               "a production device");
      r.advise("Keep the payload non-destructive: open a document, type a "
               "marker, stop there");
    } else {
      r.advise("A device that does not advertise HID cannot be keyboard-injected "
               "over Bluetooth");
    }
    r.advise("Require confirmation for new HID devices and disable 'Allow "
             "Bluetooth keyboard' on unattended hosts");
    return r;
  }
};

REGISTER_MODULE(Blueducky);
} // namespace
