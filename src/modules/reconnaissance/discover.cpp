#include "core/bt.h"
#include "core/config.h"
#include "core/module.h"
#include "core/oui.h"

namespace {
using namespace blueboy;

class Discover : public Module {
public:
  std::string name() const override { return "discover"; }
  std::string category() const override { return "reconnaissance"; }
  std::string description() const override {
    return "BR/EDR inquiry with friendly-name resolution (bounded, passive)";
  }
  std::string requirements() const override { return "root or CAP_NET_RAW"; }
  bool needs_target() const override { return false; }

  ModuleResult run(const ModuleContext &ctx) override {
    ModuleResult r;

    bt::InquiryOptions opt;
    opt.seconds = ctx.config->get_int("scan", "inquiry_seconds", 10);
    opt.max_devices = ctx.config->get_int("scan", "max_devices", 64);

    std::string err;
    const auto devices = bt::inquiry(ctx.iface, opt, err);

    if (devices.empty()) {
      r.summary = "Inquiry on " + ctx.iface + " returned no devices";
      if (!err.empty())
        r.add(err);
      r.advise("Confirm the adapter is powered (bluetoothctl power on) and "
               "that the area is in scope");
      return r;
    }

    r.success = true;
    r.summary = "Discovered " + std::to_string(devices.size()) +
                " BR/EDR device(s) on " + ctx.iface;
    for (const auto &d : devices) {
      const std::string vendor = blueboy::oui::vendor_for(d.address);
      r.add(d.address + (d.name.empty() ? "  (no friendly name)" : "  " + d.name) +
            (vendor.empty() ? "" : "  [" + vendor + "]"));
    }

    r.advise("Keep the adapter powered off outside audit windows: "
             "discoverable BR/EDR devices are visible to anyone in range");
    r.advise("Inventory the discovered addresses against the approved asset "
             "list before any follow-up assessment");
    return r;
  }
};

REGISTER_MODULE(Discover);
} // namespace
