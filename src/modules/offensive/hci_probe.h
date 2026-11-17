#pragma once
#include "core/bt.h"

#include <sstream>
#include <string>

namespace blueboy::offensive {

/// Query the peer's LMP version through hcitool when it is installed.
/// Returns the raw informative line, or an empty string when unavailable.
inline std::string remote_version(const std::string &iface,
                                  const std::string &addr) {
  if (!bt::tool_exists("hcitool"))
    return {};

  bt::ToolResult tr =
      bt::run_tool({"hcitool", "-i", iface, "rversion", addr}, 8000);
  if (tr.exit_code != 0)
    return {};

  std::istringstream in(tr.output);
  std::string line;
  while (std::getline(in, line)) {
    const auto pos = line.find_first_not_of(" \t\r");
    if (pos == std::string::npos)
      continue;
    line = line.substr(pos);
    if (line.find("Requesting") != std::string::npos)
      continue;
    return line;
  }
  return {};
}

/// True when the peer advertises a service whose 16-bit UUID matches `uuid16`.
inline bool has_service(const std::vector<bt::Service> &services,
                        uint16_t uuid16) {
  for (const auto &s : services)
    for (uint16_t c : s.classes)
      if (c == uuid16)
        return true;
  return false;
}

} // namespace blueboy::offensive
