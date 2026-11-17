#pragma once
#include <map>
#include <string>

namespace blueboy {

class Config {
public:
  bool load(const std::string &path);

  std::string get(const std::string &section, const std::string &key,
                  const std::string &def = "") const;
  int get_int(const std::string &section, const std::string &key,
              int def = 0) const;
  bool get_bool(const std::string &section, const std::string &key,
                bool def = false) const;
  double get_double(const std::string &section, const std::string &key,
                    double def = 0.0) const;

  void set(const std::string &section, const std::string &key,
           const std::string &val);
  const std::string &path() const { return path_; }

private:
  static std::string trim(const std::string &s);
  std::map<std::string, std::map<std::string, std::string>> data_;
  std::string path_;
};

} // namespace blueboy
