#pragma once
#include "core/config.h"
#include "core/module.h"
#include "core/report.h"
#include "core/roe.h"

#include <string>
#include <vector>

namespace blueboy {

/// Top-level CLI orchestration: argument parsing, consent gate, scope gate,
/// module dispatch and report collection.
class Framework {
public:
  int run(int argc, char **argv);

private:
  void print_banner() const;
  void print_usage() const;
  void print_disclaimer() const;
  void list_modules() const;
  void list_categories() const;
  int do_scan();
  int interactive();

  int run_module(const std::string &name, const std::string &target);
  int run_category(const std::string &cat, const std::string &target);
  bool target_allowed(const std::string &target);
  bool offensive_gate(Module *m, const std::string &target);
  int check_config() const;
  int check_scope(const std::string &target) const;
  std::vector<std::string> load_targets(const std::string &path) const;
  int run_targets(const std::string &module, const std::string &category,
                  const std::vector<std::string> &targets);

  bool bootstrap_environment(const std::string &cfg_path);
  bool ensure_consent(bool accept_flag);
  void emit_result(Module *m, const ModuleResult &r);
  void record(Module *m, const ModuleContext &ctx, const ModuleResult &r);

  Config config_;
  Scope scope_;
  ReportWriter writer_{"output"};
  std::vector<ReportEntry> session_;
  std::string output_dir_ = "output";
  std::string iface_ = "hci0";
  bool verbose_ = false;
  bool debug_ = false;
  bool scope_enforced_ = false;
  bool lab_ = false;
  bool iface_set_ = false;   // -i wins over the config file
  bool output_set_ = false;  // -o wins over the config file
  std::string config_path_;
  bool quiet_ = false;
  bool no_banner_ = false;
  bool dry_run_ = false;
  bool offensive_ack_ = false; // batch/category runs confirm once per process
  std::vector<std::string> excludes_;
};

} // namespace blueboy
