#include "core/bluez_dbus.h"

#include <cstring>

#ifdef BLUEBOY_HAVE_SDBUS
#include <systemd/sd-bus.h>
#endif

namespace blueboy::bluedbus {

namespace {

#ifdef BLUEBOY_HAVE_SDBUS
struct BusGuard {
  sd_bus *bus = nullptr;
  ~BusGuard() {
    if (bus)
      sd_bus_flush_close_unref(bus);
  }
};
#endif

} // namespace

bool available() {
#ifdef BLUEBOY_HAVE_SDBUS
  BusGuard guard;
  return sd_bus_open_system(&guard.bus) >= 0;
#else
  return false;
#endif
}

bool adapter_powered(const std::string &iface, bool &powered, std::string &err) {
#ifdef BLUEBOY_HAVE_SDBUS
  BusGuard guard;
  int rc = sd_bus_open_system(&guard.bus);
  if (rc < 0) {
    err = std::string("sd_bus_open_system: ") + std::strerror(-rc);
    return false;
  }

  const std::string path = "/org/bluez/" + iface;
  sd_bus_error error = SD_BUS_ERROR_NULL;
  sd_bus_message *reply = nullptr;

  rc = sd_bus_call_method(guard.bus, "org.bluez", path.c_str(),
                          "org.freedesktop.DBus.Properties", "Get", &error,
                          &reply, "ss", "org.bluez.Adapter1", "Powered");
  if (rc < 0) {
    err = error.message ? error.message : std::strerror(-rc);
    sd_bus_error_free(&error);
    return false;
  }

  int value = 0;
  rc = sd_bus_message_read(reply, "v", "b", &value);
  sd_bus_message_unref(reply);
  sd_bus_error_free(&error);
  if (rc < 0) {
    err = "unexpected Powered reply";
    return false;
  }

  powered = value != 0;
  return true;
#else
  (void)iface;
  (void)powered;
  err = "built without sd-bus support";
  return false;
#endif
}

} // namespace blueboy::bluedbus
