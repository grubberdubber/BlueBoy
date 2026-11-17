#pragma once
#include <memory>
#include <string>
#include <vector>

namespace blueboy {

class Config;

struct ModuleContext {
  std::string target; // remote BD_ADDR, empty when the module is local only
  std::string iface;  // hciX
  std::string output_dir;
  bool verbose = false;
  bool debug = false;
  Config *config = nullptr;
};

struct ModuleResult {
  bool success = false;
  std::string summary;
  std::vector<std::string> details;         // observations
  std::vector<std::string> recommendations; // hardening guidance

  void add(const std::string &d) { details.push_back(d); }
  void advise(const std::string &r) { recommendations.push_back(r); }
};

class Module {
public:
  virtual ~Module() = default;

  virtual std::string name() const = 0;
  virtual std::string category() const = 0;
  virtual std::string description() const = 0;
  virtual std::string cve() const { return "-"; }
  virtual std::string requirements() const { return "-"; }

  /// Local-only modules (e.g. adapter posture) do not need -t.
  virtual bool needs_target() const { return true; }

  /// Active modules that can disrupt or alter a peer. They are gated behind
  /// --lab, a mandatory allowlist and explicit per-target confirmation.
  virtual bool offensive() const { return false; }

  /// One-line statement of the real-world effect, shown before execution.
  virtual std::string impact() const { return {}; }

  virtual ModuleResult run(const ModuleContext &ctx) = 0;
};

class ModuleRegistry {
public:
  static ModuleRegistry &instance();

  void add(std::unique_ptr<Module> m);
  Module *get(const std::string &name);
  std::vector<Module *> all();
  std::vector<Module *> by_category(const std::string &cat);
  std::vector<std::string> categories();

private:
  ModuleRegistry() = default;
  std::vector<std::unique_ptr<Module>> modules_;
};

} // namespace blueboy

#define REGISTER_MODULE(TYPE)                                                  \
  static const bool _bb_reg_##TYPE = []() {                                    \
    ::blueboy::ModuleRegistry::instance().add(std::make_unique<TYPE>());       \
    return true;                                                               \
  }()
