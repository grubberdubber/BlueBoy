#include "core/bt.h"
#include "core/config.h"
#include "core/module.h"
#include "core/oui.h"

namespace {
using namespace blueboy;

class LeScan : public Module {
public:
  std::string name() const override { return "le_scan"; }
  std::string category() const override { return "reconnaissance"; }
  std::string description() const override {
    return "BLE advertising scan (passive listening, no connections)";
  }
  std::string requirements() const override {
    return "root or CAP_NET_ADMIN (LE scan)";
  }
  bool needs_target() const override { return false; }

  ModuleResult run(const ModuleContext &ctx) override {
    ModuleResult r;

    bt::LeScanOptions opt;
    opt.seconds = ctx.config->get_int("scan", "le_seconds", 8);
    opt.max_devices = ctx.config->get_int("scan", "max_devices", 64);

    std::string err;
    const auto devices = bt::le_scan(ctx.iface, opt, err);

    if (devices.empty()) {
      r.summary = "LE scan on " + ctx.iface + " returned no advertisers";
      if (!err.empty())
        r.add(err);
      r.advise("Check that the adapter supports BLE and is powered on");
      if (err.find("not permitted") != std::string::npos)
        r.advise("'Operation not permitted' means the kernel refused the LE "
                 "scan command: run as root, power the adapter on and stop any "
                 "other tool (bluetoothctl, btmon) holding it exclusively");
      return r;
    }

    r.success = true;
    r.summary = "Observed " + std::to_string(devices.size()) +
                " BLE advertiser(s) on " + ctx.iface;

    for (const auto &d : devices) {
      const std::string vendor = blueboy::oui::vendor_for(d.address);
      r.add(d.address + "  " + d.name + "  RSSI " +
            std::to_string(static_cast<int>(d.rssi)) + " dBm" +
            (vendor.empty() ? "" : "  [" + vendor + "]"));
    }

    r.advise("Review which devices advertise identifiable names in the area "
             "and rotate or suppress payloads where the business allows it");
    return r;
  }
};

REGISTER_MODULE(LeScan);
} // namespace
