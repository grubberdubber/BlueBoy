#pragma once
#include <string>

namespace blueboy::bluedbus {

/// True when the build has sd-bus and a system bus is reachable. BlueZ is then
/// queried through its supported D-Bus API instead of legacy HCI calls.
bool available();

/// Read org.bluez.Adapter1.Powered for `iface` (hci0, hci1, ...).
bool adapter_powered(const std::string &iface, bool &powered, std::string &err);

} // namespace blueboy::bluedbus
