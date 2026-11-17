#include "core/module.h"
#include <algorithm>
#include <cctype>

namespace blueboy {

ModuleRegistry &ModuleRegistry::instance() {
  static ModuleRegistry r;
  return r;
}

void ModuleRegistry::add(std::unique_ptr<Module> m) {
  if (m)
    modules_.push_back(std::move(m));
}

Module *ModuleRegistry::get(const std::string &name) {
  std::string want = name;
  std::transform(want.begin(), want.end(), want.begin(),
                 [](unsigned char c) { return std::tolower(c); });
  for (auto &m : modules_) {
    std::string have = m->name();
    std::transform(have.begin(), have.end(), have.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    if (have == want)
      return m.get();
  }
  return nullptr;
}

std::vector<Module *> ModuleRegistry::all() {
  std::vector<Module *> v;
  v.reserve(modules_.size());
  for (auto &m : modules_)
    v.push_back(m.get());
  std::sort(v.begin(), v.end(),
            [](Module *a, Module *b) { return a->name() < b->name(); });
  return v;
}

std::vector<Module *> ModuleRegistry::by_category(const std::string &cat) {
  std::vector<Module *> v;
  for (auto &m : modules_)
    if (m->category() == cat)
      v.push_back(m.get());
  return v;
}

std::vector<std::string> ModuleRegistry::categories() {
  std::vector<std::string> v;
  for (auto &m : modules_)
    if (std::find(v.begin(), v.end(), m->category()) == v.end())
      v.push_back(m->category());
  std::sort(v.begin(), v.end());
  return v;
}

} // namespace blueboy
