#include "core/bt.h"
#include "core/module.h"

#include <sstream>

namespace {
using namespace blueboy;

std::string classes_summary(const std::vector<uint16_t> &classes) {
  if (classes.empty())
    return {};
  std::ostringstream os;
  for (std::size_t i = 0; i < classes.size(); ++i) {
    if (i)
      os << ", ";
    os << bt::profile_name(classes[i]);
  }
  return os.str();
}

class SdpEnum : public Module {
public:
  std::string name() const override { return "sdp_enum"; }
  std::string category() const override { return "reconnaissance"; }
  std::string description() const override {
    return "Enumerate SDP records and the service classes they advertise";
  }
  std::string requirements() const override { return "root or CAP_NET_RAW"; }

  ModuleResult run(const ModuleContext &ctx) override {
    ModuleResult r;

    std::string err;
    const auto services = bt::sdp_services(ctx.target, err);

    if (services.empty()) {
      r.summary = "No SDP records could be read from " + ctx.target;
      if (!err.empty())
        r.add(err);
      r.advise("A peer that refuses SDP browsing is usually configured "
               "non-discoverable; that is a good default, not a finding");
      return r;
    }

    r.success = true;
    r.summary = "Enumerated " + std::to_string(services.size()) +
                " SDP record(s) on " + ctx.target;

    for (const auto &s : services) {
      std::ostringstream os;
      os << "handle 0x" << std::hex << s.handle << std::dec << "  " << s.name;
      const auto classes = classes_summary(s.classes);
      if (!classes.empty())
        os << "  [" << classes << "]";
      if (!s.transport.empty())
        os << "  via " << s.transport;
      r.add(os.str());
    }

    r.advise("Publish only the service records the device actually needs; "
             "every record is remotely enumerable");
    r.advise("Re-check the class list against the current Bluetooth assigned "
             "numbers if a service name looks unexpected");
    return r;
  }
};

REGISTER_MODULE(SdpEnum);
} // namespace
