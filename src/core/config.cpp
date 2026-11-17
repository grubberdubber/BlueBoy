#include "core/config.h"
#include <cstdlib>
#include <fstream>

namespace blueboy {

std::string Config::trim(const std::string &s) {
  const char *ws = " \t\r\n";
  auto b = s.find_first_not_of(ws);
  if (b == std::string::npos)
    return "";
  auto e = s.find_last_not_of(ws);
  return s.substr(b, e - b + 1);
}

bool Config::load(const std::string &path) {
  std::ifstream f(path);
  if (!f.is_open())
    return false;
  path_ = path;

  std::string line, section = "general";
  while (std::getline(f, line)) {
    std::string t = trim(line);
    if (t.empty() || t[0] == '#' || t[0] == ';')
      continue;
    if (t[0] == '[') {
      auto end = t.find(']');
      if (end != std::string::npos)
        section = trim(t.substr(1, end - 1));
      continue;
    }
    auto eq = t.find('=');
    if (eq == std::string::npos)
      continue;
    data_[section][trim(t.substr(0, eq))] = trim(t.substr(eq + 1));
  }
  return true;
}

std::string Config::get(const std::string &section, const std::string &key,
                        const std::string &def) const {
  auto s = data_.find(section);
  if (s == data_.end())
    return def;
  auto k = s->second.find(key);
  return (k == s->second.end()) ? def : k->second;
}

int Config::get_int(const std::string &s, const std::string &k, int def) const {
  std::string v = get(s, k, "");
  return v.empty() ? def : std::atoi(v.c_str());
}

bool Config::get_bool(const std::string &s, const std::string &k,
                      bool def) const {
  std::string v = get(s, k, "");
  if (v.empty())
    return def;
  return (v == "1" || v == "true" || v == "yes" || v == "on");
}

double Config::get_double(const std::string &s, const std::string &k,
                          double def) const {
  std::string v = get(s, k, "");
  return v.empty() ? def : std::atof(v.c_str());
}

void Config::set(const std::string &s, const std::string &k,
                 const std::string &v) {
  data_[s][k] = v;
}

} // namespace blueboy
