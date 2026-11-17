#include "core/oui.h"

#include <cctype>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace blueboy::oui {

namespace {

const char *kDatabases[] = {
    "/usr/share/hwdata/oui.txt",
    "/usr/share/ieee-data/oui.txt",
    "/usr/share/nmap/nmap-mac-prefixes",
};

bool is_hex(char c) {
  return std::isxdigit(static_cast<unsigned char>(c)) != 0;
}

std::string trim(const std::string &s) {
  const auto first = s.find_first_not_of(" \t\r\n");
  if (first == std::string::npos)
    return {};
  const auto last = s.find_last_not_of(" \t\r\n");
  return s.substr(first, last - first + 1);
}

/// Extract the first six hex digits of an address ("AA:BB:CC:DD:EE:FF").
std::string address_prefix(const std::string &addr) {
  std::string hex;
  for (const char c : addr) {
    if (is_hex(c))
      hex.push_back(static_cast<char>(std::toupper(
          static_cast<unsigned char>(c))));
    if (hex.size() == 6)
      break;
  }
  return hex.size() == 6 ? hex : std::string();
}

const std::unordered_map<std::string, std::string> &system_index() {
  static std::once_flag once;
  static std::unordered_map<std::string, std::string> index;

  std::call_once(once, [] {
    for (const char *path : kDatabases) {
      std::error_code ec;
      if (!std::filesystem::exists(path, ec) || ec)
        continue;
      std::ifstream in(path);
      if (!in)
        continue;

      std::string line, prefix, vendor;
      while (std::getline(in, line)) {
        if (parse_oui_line(line, prefix, vendor))
          index.emplace(prefix, vendor);
      }
      if (!index.empty())
        break;
    }
  });

  return index;
}

} // namespace

std::string prefix_key(const std::string &prefix) {
  std::string hex;
  for (const char c : prefix) {
    if (is_hex(c)) {
      hex.push_back(static_cast<char>(std::toupper(
          static_cast<unsigned char>(c))));
      if (hex.size() == 6)
        break;
      continue;
    }
    // Separators are allowed between octets; anything else ends the prefix.
    if (c == '-' || c == ':' || c == '.' || c == ' ')
      continue;
    return {};
  }
  return hex.size() == 6 ? hex : std::string();
}

bool parse_oui_line(const std::string &line, std::string &prefix_out,
                    std::string &vendor_out) {
  const std::string text = trim(line);
  if (text.empty() || text[0] == '#')
    return false;
  if (text.rfind("OUI/MA-L", 0) == 0 || text.rfind("company_id", 0) == 0)
    return false;

  // IEEE: "00-1A-7D   (hex)\t\tVendor Name"
  if (text.size() > 8 && text[2] == '-' && text[5] == '-') {
    const std::string key = prefix_key(text.substr(0, 8));
    if (key.empty())
      return false;
    const auto marker = text.find("(hex)");
    if (marker == std::string::npos)
      return false;
    const std::string vendor = trim(text.substr(marker + 5));
    if (vendor.empty())
      return false;
    prefix_out = key;
    vendor_out = vendor;
    return true;
  }

  // nmap: "001A7D Vendor Name"
  if (text.size() > 7 && text[0] != ' ' && text[6] == ' ') {
    const std::string key = prefix_key(text.substr(0, 6));
    if (key.empty())
      return false;
    const std::string vendor = trim(text.substr(7));
    if (vendor.empty())
      return false;
    prefix_out = key;
    vendor_out = vendor;
    return true;
  }

  return false;
}

std::string vendor_from_file(const std::string &path, const std::string &addr) {
  const std::string key = address_prefix(addr);
  if (key.empty())
    return {};

  std::ifstream in(path);
  if (!in)
    return {};

  std::string line, prefix, vendor;
  while (std::getline(in, line)) {
    if (!parse_oui_line(line, prefix, vendor))
      continue;
    if (prefix == key)
      return vendor;
  }
  return {};
}

std::string vendor_for(const std::string &addr) {
  const std::string key = address_prefix(addr);
  if (key.empty())
    return {};

  const auto &index = system_index();
  const auto it = index.find(key);
  return it == index.end() ? std::string() : it->second;
}

} // namespace blueboy::oui
