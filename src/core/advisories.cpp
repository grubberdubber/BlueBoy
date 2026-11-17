#include "core/advisories.h"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <sstream>

namespace blueboy {

namespace {

std::string trim(const std::string &s) {
  const auto first = s.find_first_not_of(" \t\r\n");
  if (first == std::string::npos)
    return {};
  const auto last = s.find_last_not_of(" \t\r\n");
  return s.substr(first, last - first + 1);
}

std::string lower(std::string s) {
  std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
    return static_cast<char>(std::tolower(c));
  });
  return s;
}

std::vector<std::string> split_list(const std::string &value) {
  std::vector<std::string> out;
  std::istringstream in(value);
  std::string item;
  while (std::getline(in, item, ',')) {
    item = trim(item);
    if (!item.empty())
      out.push_back(item);
  }
  return out;
}

bool known_match(const std::string &m) {
  return m == "any" || m == "sdp" || m == "l2cap" || m == "rfcomm" ||
         m == "fast_pair";
}

bool known_severity(const std::string &s) {
  return s == "critical" || s == "high" || s == "medium" || s == "low" ||
         s == "info";
}

bool contains_ci(const std::string &haystack, const std::string &needle) {
  return lower(haystack).find(lower(needle)) != std::string::npos;
}

} // namespace

int severity_rank(const std::string &severity) {
  if (severity == "critical")
    return 0;
  if (severity == "high")
    return 1;
  if (severity == "medium")
    return 2;
  if (severity == "low")
    return 3;
  return 4;
}

std::vector<Advisory> load_advisories(const std::string &path,
                                      std::string &err) {
  std::vector<Advisory> out;

  std::ifstream in(path);
  if (!in) {
    err = "advisory database not readable: " + path;
    return out;
  }

  Advisory current;
  bool have_entry = false;
  std::string line;
  int lineno = 0;

  auto flush = [&] {
    if (!have_entry)
      return;
    if (current.name.empty() || current.match.empty()) {
      err += "incomplete advisory [" + current.key + "]; ";
      have_entry = false;
      return;
    }
    if (!known_match(current.match)) {
      err += "unknown match '" + current.match + "' in [" + current.key +
             "]; ";
      have_entry = false;
      return;
    }
    if (!known_severity(current.severity)) {
      err += "unknown severity '" + current.severity + "' in [" + current.key +
             "]; ";
      current.severity = "info";
    }
    out.push_back(current);
    have_entry = false;
  };

  while (std::getline(in, line)) {
    ++lineno;
    const std::string text = trim(line);
    if (text.empty() || text[0] == '#')
      continue;

    if (text.front() == '[' && text.back() == ']') {
      flush();
      current = Advisory{};
      current.key = trim(text.substr(1, text.size() - 2));
      have_entry = true;
      continue;
    }

    const auto eq = text.find('=');
    if (eq == std::string::npos) {
      err += "malformed line " + std::to_string(lineno) + "; ";
      continue;
    }

    const std::string key = trim(text.substr(0, eq));
    const std::string value = trim(text.substr(eq + 1));

    if (key == "name")
      current.name = value;
    else if (key == "cves")
      current.cves = value;
    else if (key == "class")
      current.cls = value;
    else if (key == "severity")
      current.severity = lower(value);
    else if (key == "match")
      current.match = lower(value);
    else if (key == "vendors")
      current.vendors = split_list(value);
    else if (key == "condition")
      current.condition = value;
    else if (key == "fixed")
      current.fixed = value;
    else if (key == "refs")
      current.refs = value;
  }

  flush();

  std::sort(out.begin(), out.end(), [](const Advisory &a, const Advisory &b) {
    return severity_rank(a.severity) < severity_rank(b.severity);
  });

  if (err.size() > 2 && err.back() == ' ' && err[err.size() - 2] == ';')
    err.erase(err.size() - 2);

  return out;
}

bool advisory_matches(const Advisory &a, bool sdp, bool l2cap, bool rfcomm,
                      bool fast_pair, const std::string &vendor) {
  bool surface = false;
  if (a.match == "any")
    surface = sdp || l2cap || rfcomm;
  else if (a.match == "sdp")
    surface = sdp;
  else if (a.match == "l2cap")
    surface = l2cap;
  else if (a.match == "rfcomm")
    surface = rfcomm;
  else if (a.match == "fast_pair")
    surface = fast_pair;

  if (!surface)
    return false;

  if (a.vendors.empty())
    return true;
  if (vendor.empty())
    return false;

  for (const auto &v : a.vendors)
    if (contains_ci(vendor, v))
      return true;
  return false;
}

} // namespace blueboy
