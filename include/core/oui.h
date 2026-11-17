#pragma once
#include <string>

namespace blueboy::oui {

/// Vendor for a BD_ADDR, using the first readable system OUI database
/// (hwdata, ieee-data, nmap). Returns an empty string when unknown.
std::string vendor_for(const std::string &addr);

/// Same lookup against one explicit database file. Exposed for tests.
std::string vendor_from_file(const std::string &path, const std::string &addr);

/// Normalise an OUI ("00-1A-7D", "00:1a:7d", "001A7D") to "001A7D".
/// Returns an empty string when the input is not a 24-bit prefix.
std::string prefix_key(const std::string &prefix);

/// Parse one database line into `out` (prefix -> vendor). Returns true on a
/// recognised line. Handles both IEEE oui.txt and nmap's mac-prefixes format.
bool parse_oui_line(const std::string &line,
                    std::string &prefix_out, std::string &vendor_out);

} // namespace blueboy::oui
