#include "core/bluez_dbus.h"
#include "core/bt.h"
#include "core/module.h"

#include <iomanip>
#include <sstream>

namespace {
using namespace blueboy;

std::string class_of_device(uint32_t cod) {
  std::ostringstream os;
  os << "0x" << std::hex << std::setw(6) << std::setfill('0') << cod;
  return os.str();
}

class AdapterPosture : public Module {
public:
  std::string name() const override { return "adapter_posture"; }
  std::string category() const override { return "hardening"; }
  std::string description() const override {
    return "Review the local adapter configuration against hardening basics";
  }
  std::string requirements() const override { return "root or CAP_NET_RAW"; }
  bool needs_target() const override { return false; }

  ModuleResult run(const ModuleContext &ctx) override {
    ModuleResult r;

    const bt::AdapterInfo info = bt::adapter_info(ctx.iface);
    if (!info.error.empty()) {
      r.summary = "Could not read adapter " + ctx.iface + ": " + info.error;
      r.advise("Confirm the controller exists (hciconfig -a) and that you run "
               "with CAP_NET_RAW");
      return r;
    }

    int findings = 0;
    r.add("Address: " + (info.address.empty() ? "(unreadable)" : info.address));
    r.add("Friendly name: " + (info.name.empty() ? "(unset)" : info.name));
    r.add("Manufacturer: " +
          (info.manufacturer.empty() ? "(unknown)" : info.manufacturer));
    r.add("HCI/LMP: " + bt::hci_version_string(info.hci_version) + " / " +
          bt::hci_version_string(info.lmp_version));
    r.add("Class of device: " + class_of_device(info.dev_class));
    r.add(std::string("Discoverable: ") + (info.discoverable ? "yes" : "no"));
    r.add(std::string("Connectable: ") + (info.connectable ? "yes" : "no"));
    r.add(std::string("Secure Simple Pairing: ") +
          (info.secure_simple_pairing ? "enabled" : "disabled"));
    r.add(std::string("BLE supported: ") + (info.le_supported ? "yes" : "no"));

    // BlueZ is authoritative about power state; read it over D-Bus when the
    // build has sd-bus instead of guessing from HCI failures.
    bool powered = false;
    std::string dbus_err;
    if (bluedbus::adapter_powered(ctx.iface, powered, dbus_err))
      r.add(std::string("BlueZ powered (D-Bus): ") + (powered ? "yes" : "no"));
    else if (bluedbus::available())
      r.add("BlueZ D-Bus: " + dbus_err);
    else
      r.add("BlueZ D-Bus: sd-bus not available in this build");

    if (info.discoverable) {
      ++findings;
      r.advise("Set the adapter non-discoverable outside pairing windows "
               "(bluetoothctl discoverable off)");
    }
    if (!info.secure_simple_pairing) {
      ++findings;
      r.advise("Enable Secure Simple Pairing; legacy PIN pairing is far easier "
               "to brute force");
    }
    if (info.discoverable && info.connectable) {
      ++findings;
      r.advise("A discoverable and connectable adapter accepts unsolicited "
               "connection attempts from any device in range");
    }
    if (info.hci_version >= 0 && info.hci_version < 6) {
      ++findings;
      r.advise("The controller predates Bluetooth 4.0; plan a hardware refresh "
               "for managed fleets");
    }
    if (info.le_supported) {
      r.advise("If BLE is not required, disable it to shrink the attack surface "
               "on handheld and desktop systems");
    }

    r.success = true;
    r.summary = findings == 0
                    ? "No posture issues found on " + ctx.iface
                    : std::to_string(findings) + " posture issue(s) on " +
                          ctx.iface;
    return r;
  }
};

REGISTER_MODULE(AdapterPosture);
} // namespace
