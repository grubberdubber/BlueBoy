#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace blueboy::bt {

/// A BR/EDR or BLE peer discovered during reconnaissance.
struct Device {
  std::string address;
  std::string name;
  int8_t rssi = 0;
  bool ble = false;
};

/// One SDP record exposed by a peer.
struct Service {
  uint32_t handle = 0;
  std::string name;
  std::vector<uint16_t> classes; // 16-bit UUIDs advertised by the record
  int rfcomm_channel = -1;
  int l2cap_psm = -1;
  std::string transport;
};

struct PingStats {
  int sent = 0;
  int received = 0;
  double min_ms = 0.0;
  double max_ms = 0.0;
  double avg_ms = 0.0;
  std::string error; // why no probe left the adapter, when sent == 0
};

struct InquiryOptions {
  int seconds = 10;
  int max_devices = 64;
};

struct LeScanOptions {
  int seconds = 8;
  int max_devices = 64;
};

/// Local adapter configuration read through HCI informational commands.
struct AdapterInfo {
  std::string address;
  std::string name;
  std::string manufacturer;
  int hci_version = -1;
  int lmp_version = -1;
  int hci_revision = 0;
  uint32_t dev_class = 0;
  bool discoverable = false;
  bool connectable = false;
  bool secure_simple_pairing = false;
  bool le_supported = false;
  std::string error;
};

/// Normalise a BD_ADDR to BlueZ's "AA:BB:CC:DD:EE:FF" form.
/// Returns the input untouched when it is not a usable address.
std::string normalize_addr(const std::string &in);
bool is_valid_addr(const std::string &in);

bool iface_exists(const std::string &iface);
int devid_from_iface(const std::string &iface);

std::vector<Device> inquiry(const std::string &iface, const InquiryOptions &opt,
                            std::string &err);
bool read_remote_name(const std::string &iface, const std::string &addr,
                      std::string &name, int timeout_ms);
std::vector<Device> le_scan(const std::string &iface, const LeScanOptions &opt,
                            std::string &err);

/// Send a small, bounded number of L2CAP echo requests (non-disruptive).
PingStats l2ping(const std::string &addr, int size, int count, int timeout_ms);

/// Try to open one L2CAP channel on `psm` without sending data.
/// Returns 0 when the peer accepted the connection, -1 otherwise.
int l2cap_probe(const std::string &addr, int psm, int timeout_ms);

// --- Active lab primitives ---------------------------------------------------
// These are used by the offensive module pack. Every argument is clamped inside
// the implementation (payload <= 600 B, rate <= 500 pps, duration <= 30 s,
// connections <= 64, cycles <= 200) so no config value can lift the ceiling.

/// Echo burst against PSM 1. Returns the number of requests queued.
int l2cap_echo_burst(const std::string &addr, int payload, int rate_pps,
                     int duration_s, int &replied);

/// Open up to `wanted` L2CAP connections, hold them, then close.
/// Returns the number of connections actually established.
int l2cap_connect_burst(const std::string &addr, uint16_t psm, int wanted,
                        int hold_s);

/// Rapid connect/disconnect cycles against one PSM. Returns successes.
int l2cap_connect_cycles(const std::string &addr, uint16_t psm, int cycles);

bool rfcomm_connect(const std::string &addr, int channel, int timeout_ms,
                    int &sock);
bool rfcomm_send(int sock, const std::string &data);
std::string rfcomm_read(int sock, int timeout_ms);

struct ToolResult {
  int exit_code = -1;
  std::string output;
};

/// Execute an external tool with an argv vector (never through a shell).
/// `cwd`, when set, becomes the child's working directory.
ToolResult run_tool(const std::vector<std::string> &argv,
                    int timeout_ms = 30000, const std::string &cwd = {});
bool tool_exists(const std::string &tool);

/// Enumerate the peer's SDP database (read-only).
std::vector<Service> sdp_services(const std::string &addr, std::string &err);

AdapterInfo adapter_info(const std::string &iface);

/// Human readable name for a 16-bit Bluetooth service class UUID.
std::string profile_name(uint16_t uuid16);

/// Human readable Core specification version for an HCI/LMP version byte.
std::string hci_version_string(int version);

} // namespace blueboy::bt
