#include "core/bluez_store.h"
#include "core/bt.h"

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <unistd.h>

namespace blueboy::bluez {

namespace fs = std::filesystem;

namespace {

std::string trim(const std::string &s) {
  const auto first = s.find_first_not_of(" \t\r\n");
  if (first == std::string::npos)
    return {};
  const auto last = s.find_last_not_of(" \t\r\n");
  return s.substr(first, last - first + 1);
}

} // namespace

std::string key_type_label(int type) {
  switch (type) {
  case 0:
  case 1:
  case 2:
  case 3:
  case 4:
  case 5:
    return "legacy PIN";
  case 6:
    return "SSP unauthenticated";
  case 7:
    return "SSP authenticated";
  case 8:
    return "Secure Connections";
  default:
    return "unknown";
  }
}

bool parse_settings_text(const std::string &text, Bond &bond) {
  std::istringstream in(text);
  std::string line;
  std::string section;
  bool recognised = false;

  while (std::getline(in, line)) {
    line = trim(line);
    if (line.empty() || line[0] == '#')
      continue;

    if (line.front() == '[' && line.back() == ']') {
      section = line.substr(1, line.size() - 2);
      continue;
    }

    const auto eq = line.find('=');
    if (eq == std::string::npos)
      continue;
    const std::string key = trim(line.substr(0, eq));
    const std::string value = trim(line.substr(eq + 1));

    if (section == "General" && key == "Name") {
      bond.name = value;
      recognised = true;
    } else if (section == "LinkKey") {
      if (key == "Key" && !value.empty()) {
        bond.has_link_key = true;
        recognised = true;
      } else if (key == "Type") {
        bond.key_type = key_type_label(std::atoi(value.c_str()));
        recognised = true;
      }
    } else if (section == "LongTermKey" && key == "Key") {
      // LE long-term key: the bond exists even without a classic link key.
      if (!value.empty())
        recognised = true;
    }
  }

  return recognised;
}

std::vector<Bond> read_bonds(const std::string &store, std::string &err) {
  std::vector<Bond> bonds;

  std::error_code ec;
  if (!fs::exists(store, ec) || ec) {
    err = "bond store not found: " + store;
    return bonds;
  }
  if (::access(store.c_str(), R_OK) != 0) {
    err = "bond store not readable by this user: " + store +
          " (run as root to inventory bonds)";
    return bonds;
  }

  for (const auto &entry : fs::directory_iterator(store, ec)) {
    if (ec) {
      err = ec.message();
      break;
    }
    if (!entry.is_directory())
      continue;

    fs::path file = entry.path() / "settings";
    if (!fs::exists(file))
      file = entry.path() / "info";
    if (!fs::exists(file))
      continue;

    std::ifstream in(file);
    if (!in)
      continue;

    std::stringstream buffer;
    buffer << in.rdbuf();

    Bond bond;
    if (!parse_settings_text(buffer.str(), bond))
      continue;

    bond.address = bt::normalize_addr(entry.path().filename().string());
    bond.source = file.string();

    std::error_code time_ec;
    const auto mtime = fs::last_write_time(file, time_ec);
    if (!time_ec) {
      const auto now = fs::file_time_type::clock::now();
      const auto age = std::chrono::duration_cast<std::chrono::hours>(
          now - mtime);
      bond.age_days = age.count() / 24;
    }

    bonds.push_back(std::move(bond));
  }

  return bonds;
}

} // namespace blueboy::bluez
