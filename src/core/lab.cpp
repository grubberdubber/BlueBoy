#include "core/lab.h"

namespace blueboy {

LabDecision evaluate_lab(bool lab, bool in_scope) {
  if (!lab)
    return LabDecision::LabFlagMissing;
  if (!in_scope)
    return LabDecision::OutOfScope;
  return LabDecision::Allowed;
}

std::string lab_denial_reason(LabDecision decision) {
  switch (decision) {
  case LabDecision::LabFlagMissing:
    return "This is an offensive module. Re-run with --lab and read its impact "
           "statement first.";
  case LabDecision::OutOfScope:
    return "The target is not in the authorised allowlist. Add it only if the "
           "signed rules of engagement cover that device.";
  case LabDecision::Allowed:
    break;
  }
  return {};
}

} // namespace blueboy
