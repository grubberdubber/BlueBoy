#include "core/bt.h"
#include "core/module.h"

#include <algorithm>
#include <map>
#include <sstream>

namespace {
using namespace blueboy;

struct ExposureRule {
  uint16_t uuid;
  int weight; // 3 = high, 2 = medium, 1 = low exposure
  const char *advice;
};

const ExposureRule kRules[] = {
    {0x1106, 3,
     "Disable OBEX File Transfer unless a signed-off use case requires it; it "
     "gives a bonded peer filesystem-level browsing"},
    {0x112F, 3,
     "Restrict Phonebook Access Server to bonded, trusted devices and require "
     "confirmation for every contact transfer"},
    {0x1132, 3,
     "Disable Message Access Server on managed devices unless SMS access is an "
     "approved function"},
    {0x1124, 2,
     "HID lets a peer act as a keyboard: require pairing confirmation and keep "
     "the device non-discoverable in shared spaces"},
    {0x1101, 2,
     "Remove Serial Port Profile services that are not operationally required "
     "and enforce authentication on the remaining ones"},
    {0x1113, 2,
     "SIM Access Server can expose SIM credentials; keep it disabled unless an "
     "approved automotive use case requires it"},
    {0x1105, 2,
     "Keep OBEX Object Push behind a confirmation prompt so unsolicited files "
     "are never accepted silently"},
    {0x1115, 2,
     "Disable PAN User unless the device genuinely needs a personal area "
     "network"},
    {0x1116, 2,
     "PAN Network Access Point provides routed network access over Bluetooth; "
     "enable it deliberately and log its clients"},
    {0x1117, 2,
     "PAN Group Ad-hoc Network lets peers form a group network; restrict it to "
     "authorised devices"},
    {0x1108, 1,
     "Headset profile is expected for audio hardware; confirm the pairing "
     "policy still requires authentication"},
    {0x111E, 1,
     "Handsfree profile is expected for audio hardware; confirm the pairing "
     "policy still requires authentication"},
    {0x110D, 1,
     "A2DP audio streaming: low exposure, but verify only trusted sources can "
     "connect"},
    {0x110C, 1,
     "A/V Remote Control can drive media playback; validate that control "
     "requires a trusted link"},
};

const ExposureRule *find_rule(uint16_t uuid) {
  for (const auto &rule : kRules)
    if (rule.uuid == uuid)
      return &rule;
  return nullptr;
}

std::string weight_label(int weight) {
  switch (weight) {
  case 3:
    return "high";
  case 2:
    return "medium";
  default:
    return "low";
  }
}

class ServiceAudit : public Module {
public:
  std::string name() const override { return "service_audit"; }
  std::string category() const override { return "assessment"; }
  std::string description() const override {
    return "Rate the exposure of every service advertised over SDP";
  }
  std::string requirements() const override { return "root or CAP_NET_RAW"; }

  ModuleResult run(const ModuleContext &ctx) override {
    ModuleResult r;

    std::string err;
    const auto services = bt::sdp_services(ctx.target, err);

    if (services.empty()) {
      r.summary = "Could not read the SDP database of " + ctx.target;
      if (!err.empty())
        r.add(err);
      r.advise("Confirm the peer is powered, in range and discoverable before "
               "concluding it exposes nothing");
      return r;
    }

    std::map<uint16_t, int> seen; // uuid -> worst weight
    std::vector<std::string> advice;
    int high = 0, medium = 0, low = 0;

    for (const auto &s : services) {
      std::ostringstream line;
      line << s.name;
      if (!s.transport.empty())
        line << "  via " << s.transport;

      bool rated = false;
      for (uint16_t uuid : s.classes) {
        const ExposureRule *rule = find_rule(uuid);
        if (!rule)
          continue;
        rated = true;

        auto it = seen.find(uuid);
        if (it == seen.end()) {
          seen[uuid] = rule->weight;
          advice.push_back(rule->advice);
          if (rule->weight == 3)
            high++;
          else if (rule->weight == 2)
            medium++;
          else
            low++;
        } else if (rule->weight > it->second) {
          it->second = rule->weight;
        }

        line << "\n      " << weight_label(rule->weight) << " exposure: "
             << bt::profile_name(uuid);
      }

      if (!rated)
        line << "\n      informational: no risk rule for the advertised classes";
      r.add(line.str());
    }

    r.success = true;
    std::ostringstream summary;
    summary << "Reviewed " << services.size() << " service(s): " << high
            << " high, " << medium << " medium, " << low << " low exposure";
    r.summary = summary.str();

    r.add("Assessment is based on advertised SDP records only; no service was "
          "contacted or exercised");
    for (const auto &a : advice)
      r.advise(a);

    if (high == 0 && medium == 0) {
      r.advise("Exposure is limited to expected audio/PnP profiles; re-test "
               "after firmware or pairing-policy changes");
    }
    return r;
  }
};

REGISTER_MODULE(ServiceAudit);
} // namespace
