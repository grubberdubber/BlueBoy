#pragma once
#include <string>

namespace blueboy {

/// Result of the pre-flight checks that guard offensive modules.
enum class LabDecision {
  Allowed,
  LabFlagMissing, // --lab not supplied
  OutOfScope,     // scope enforcement is on and the target is not allowlisted
};

/// `in_scope` is true when scope enforcement is off or the target is listed.
LabDecision evaluate_lab(bool lab, bool in_scope);

/// Operator-facing explanation for a denial, including the fix.
std::string lab_denial_reason(LabDecision decision);

} // namespace blueboy
