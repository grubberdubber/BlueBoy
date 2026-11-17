#include "core/bt.h"
#include "core/logger.h"

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <bluetooth/l2cap.h>
#include <bluetooth/rfcomm.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <filesystem>
#include <poll.h>
#include <csignal>
#include <cstdlib>
#include <sys/socket.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>

namespace blueboy::bt {

int l2cap_probe(const std::string &addr, int psm, int timeout_ms) {
  if (psm < 1 || psm > 0xffff)
    return -1;

  bdaddr_t ba;
  if (str2ba(addr.c_str(), &ba) < 0)
    return -1;

  int sk = socket(AF_BLUETOOTH, SOCK_RAW | SOCK_CLOEXEC, BTPROTO_L2CAP);
  if (sk < 0)
    return -1;

  const int flags = fcntl(sk, F_GETFL, 0);
  fcntl(sk, F_SETFL, flags | O_NONBLOCK);

  sockaddr_l2 la{};
  la.l2_family = AF_BLUETOOTH;
  la.l2_bdaddr = ba;
  la.l2_psm = htobs(static_cast<uint16_t>(psm));

  int rc = connect(sk, reinterpret_cast<sockaddr *>(&la), sizeof(la));
  if (rc < 0 && errno != EINPROGRESS) {
    ::close(sk);
    return -1;
  }

  if (rc < 0) {
    const int wait = timeout_ms < 100 ? 100 : (timeout_ms > 5000 ? 5000 : timeout_ms);
    pollfd pfd{sk, POLLOUT, 0};
    if (poll(&pfd, 1, wait) <= 0) {
      ::close(sk);
      return -1;
    }
    int so_error = 0;
    socklen_t len = sizeof(so_error);
    if (getsockopt(sk, SOL_SOCKET, SO_ERROR, &so_error, &len) < 0 ||
        so_error != 0) {
      ::close(sk);
      return -1;
    }
  }

  ::close(sk);
  return 0;
}

namespace {

// Hard safety bounds. They keep every operation bounded even if a configuration
// file asks for something larger.
constexpr int kMaxInquirySeconds = 60;
constexpr int kMaxDevices = 256;
constexpr int kMaxEchoPayload = 512;
constexpr int kMaxEchoCount = 32;

// Ceilings for the active lab primitives. These live in code, not in the
// configuration file, so an audit profile cannot raise them.
constexpr int kMaxBurstPayload = 600;
constexpr int kMaxBurstRate = 500;
constexpr int kMaxBurstDuration = 30;
constexpr int kMaxBurstConnections = 64;
constexpr int kMaxCycleCount = 200;
constexpr int kMaxRfcommChannel = 30;

struct L2capHdr {
  uint8_t code;
  uint8_t ident;
  uint16_t len;
} __attribute__((packed));

// BlueZ already defines L2CAP_ECHO_REQ/RSP as macros, so use local names.
constexpr uint8_t kEchoReqCode = 0x08;
constexpr uint8_t kEchoRspCode = 0x09;

double now_ms() {
  using namespace std::chrono;
  return duration_cast<duration<double, std::milli>>(
             steady_clock::now().time_since_epoch())
      .count();
}

std::string errtxt(const char *what) {
  return std::string(what) + ": " + std::strerror(errno);
}

int clamp_int(int value, int lo, int hi) {
  return std::max(lo, std::min(value, hi));
}

// --- SDP data-element helpers ------------------------------------------------

void collect_class_uuids(const sdp_data_t *data, std::vector<uint16_t> &out) {
  for (const sdp_data_t *d = data; d; d = d->next) {
    if (d->dtd == SDP_UUID16) {
      out.push_back(d->val.uuid.value.uuid16);
    } else if (d->dtd == SDP_UUID32) {
      uint32_t v = d->val.uuid.value.uuid32;
      if (v <= 0xffff)
        out.push_back(static_cast<uint16_t>(v));
    } else if (d->dtd == SDP_SEQ8 || d->dtd == SDP_SEQ16 ||
               d->dtd == SDP_SEQ32) {
      collect_class_uuids(d->val.dataseq, out);
    }
  }
}

/// Walk the protocol descriptor list looking for `uuid16` and return its port
/// (L2CAP PSM or RFCOMM channel). Returns -1 when absent.
int proto_port(const sdp_data_t *list, uint16_t uuid16) {
  for (const sdp_data_t *d = list; d; d = d->next) {
    if (d->dtd != SDP_SEQ8 && d->dtd != SDP_SEQ16 && d->dtd != SDP_SEQ32)
      continue;

    const sdp_data_t *proto = d->val.dataseq;
    if (!proto || proto->dtd != SDP_UUID16)
      continue;
    if (proto->val.uuid.value.uuid16 != uuid16)
      continue;

    const sdp_data_t *port = proto->next;
    if (!port)
      continue;
    if (port->dtd == SDP_UINT16)
      return port->val.uint16;
    if (port->dtd == SDP_UINT8)
      return port->val.uint8;
  }
  return -1;
}

std::string record_name(const sdp_record_t *rec) {
  const sdp_data_t *d = sdp_data_get(rec, SDP_ATTR_SVCNAME_PRIMARY);
  if (!d || !d->val.str)
    return {};
  switch (d->dtd) {
  case SDP_TEXT_STR8:
  case SDP_TEXT_STR16:
  case SDP_TEXT_STR32:
    return d->val.str;
  default:
    return {};
  }
}

// --- HCI helpers -------------------------------------------------------------

int open_hci_raw(int devid, std::string &err) {
  int dd = socket(AF_BLUETOOTH, SOCK_RAW | SOCK_CLOEXEC, BTPROTO_HCI);
  if (dd < 0) {
    err = errtxt("hci socket");
    return -1;
  }

  sockaddr_hci addr{};
  addr.hci_family = AF_BLUETOOTH;
  addr.hci_dev = static_cast<uint16_t>(devid);
  addr.hci_channel = HCI_CHANNEL_RAW;
  if (bind(dd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) < 0) {
    err = errtxt("hci bind");
    ::close(dd);
    return -1;
  }

  hci_filter filter;
  hci_filter_clear(&filter);
  hci_filter_set_ptype(HCI_EVENT_PKT, &filter);
  hci_filter_set_event(EVT_LE_META_EVENT, &filter);
  if (setsockopt(dd, SOL_HCI, HCI_FILTER, &filter, sizeof(filter)) < 0) {
    err = errtxt("hci filter");
    ::close(dd);
    return -1;
  }
  return dd;
}

bool read_scan_enable(int dd, uint8_t &enable) {
  // hci_read_scan_enable is not exported by every BlueZ release, so issue the
  // informational command directly.
  struct {
    uint8_t status;
    uint8_t enable;
  } __attribute__((packed)) rp {};

  hci_request rq{};
  rq.ogf = OGF_INFO_PARAM;
  rq.ocf = OCF_READ_SCAN_ENABLE;
  rq.rparam = &rp;
  rq.rlen = sizeof(rp);

  if (hci_send_req(dd, &rq, 1000) < 0 || rp.status != 0)
    return false;
  enable = rp.enable;
  return true;
}

std::string eir_name(const uint8_t *data, int len) {
  const uint8_t *p = data;
  int remaining = len;
  while (remaining > 1) {
    uint8_t field_len = p[0];
    if (field_len == 0 || field_len + 1 > remaining)
      break;
    uint8_t type = p[1];
    if ((type == 0x08 || type == 0x09) && field_len > 1)
      return std::string(reinterpret_cast<const char *>(p + 2), field_len - 1);
    p += field_len + 1;
    remaining -= field_len + 1;
  }
  return {};
}

std::string hci_version_name(int version) {
  switch (version) {
  case 0:
    return "1.0b";
  case 1:
    return "1.1";
  case 2:
    return "1.2";
  case 3:
    return "2.0";
  case 4:
    return "2.1";
  case 5:
    return "3.0";
  case 6:
    return "4.0";
  case 7:
    return "4.1";
  case 8:
    return "4.2";
  case 9:
    return "5.0";
  case 10:
    return "5.1";
  case 11:
    return "5.2";
  case 12:
    return "5.3";
  case 13:
    return "5.4";
  default:
    return "unknown";
  }
}

} // namespace

std::string normalize_addr(const std::string &in) {
  bdaddr_t ba;
  if (str2ba(in.c_str(), &ba) < 0)
    return in;
  char buf[19] = {0};
  ba2str(&ba, buf);
  return buf;
}

bool is_valid_addr(const std::string &in) {
  bdaddr_t ba;
  return str2ba(in.c_str(), &ba) == 0;
}

int devid_from_iface(const std::string &iface) {
  if (iface.empty())
    return hci_get_route(nullptr);
  return hci_devid(iface.c_str());
}

bool iface_exists(const std::string &iface) { return devid_from_iface(iface) >= 0; }
std::vector<Device> inquiry(const std::string &iface, const InquiryOptions &opt,
                            std::string &err) {
  std::vector<Device> out;
  int devid = devid_from_iface(iface);
  if (devid < 0) {
    err = "adapter not found: " + iface;
    return out;
  }

  int seconds = clamp_int(opt.seconds, 1, kMaxInquirySeconds);
  int max_dev = clamp_int(opt.max_devices, 1, kMaxDevices);
  int length = std::max(1, (seconds * 100) / 128); // HCI units of 1.28 s

  inquiry_info *devices = nullptr;
  int found = hci_inquiry(devid, length, max_dev, nullptr, &devices,
                          IREQ_CACHE_FLUSH);
  if (found < 0) {
    err = errtxt("hci_inquiry");
    return out;
  }

  int dd = hci_open_dev(devid);
  for (int i = 0; i < found; ++i) {
    Device d;
    char addr[19] = {0};
    ba2str(&devices[i].bdaddr, addr);
    d.address = addr;

    if (dd >= 0) {
      char name[249] = {0};
      if (hci_read_remote_name(dd, &devices[i].bdaddr, sizeof(name), name,
                               6000) == 0)
        d.name = name;
    }
    out.push_back(std::move(d));
  }

  if (dd >= 0)
    hci_close_dev(dd);
  free(devices);
  if (out.empty())
    err = "no devices answered the inquiry";
  return out;
}

bool read_remote_name(const std::string &iface, const std::string &addr,
                      std::string &name, int timeout_ms) {
  bdaddr_t ba;
  if (str2ba(addr.c_str(), &ba) < 0)
    return false;
  int devid = devid_from_iface(iface);
  if (devid < 0)
    return false;
  int dd = hci_open_dev(devid);
  if (dd < 0)
    return false;

  char nm[249] = {0};
  int rc = hci_read_remote_name(dd, &ba, sizeof(nm), nm, timeout_ms);
  hci_close_dev(dd);
  if (rc != 0)
    return false;
  name = nm;
  return true;
}

std::vector<Device> le_scan(const std::string &iface, const LeScanOptions &opt,
                            std::string &err) {
  std::vector<Device> out;
  int devid = devid_from_iface(iface);
  if (devid < 0) {
    err = "adapter not found: " + iface;
    return out;
  }

  int dd = open_hci_raw(devid, err);
  if (dd < 0)
    return out;

  if (hci_le_set_scan_parameters(dd, 0x01, htobs(0x0010), htobs(0x0010), 0x00,
                                 0x00, 1000) < 0) {
    err = errtxt("LE scan parameters (is the adapter powered?)");
    ::close(dd);
    return out;
  }
  if (hci_le_set_scan_enable(dd, 0x01, 0x00, 1000) < 0) {
    err = errtxt("LE scan enable");
    ::close(dd);
    return out;
  }

  const int seconds = clamp_int(opt.seconds, 1, kMaxInquirySeconds);
  const int max_dev = clamp_int(opt.max_devices, 1, kMaxDevices);

  using clock = std::chrono::steady_clock;
  const auto deadline = clock::now() + std::chrono::seconds(seconds);
  std::array<uint8_t, HCI_MAX_EVENT_SIZE> buf{};

  while (static_cast<int>(out.size()) < max_dev) {
    auto left = std::chrono::duration_cast<std::chrono::milliseconds>(
                    deadline - clock::now())
                    .count();
    if (left <= 0)
      break;

    pollfd pfd{dd, POLLIN, 0};
    int ready = poll(&pfd, 1, static_cast<int>(left));
    if (ready <= 0)
      continue;

    ssize_t n = read(dd, buf.data(), buf.size());
    if (n < 1 + static_cast<ssize_t>(HCI_EVENT_HDR_SIZE))
      continue;

    const auto *hdr =
        reinterpret_cast<const hci_event_hdr *>(buf.data() + 1);
    if (hdr->evt != EVT_LE_META_EVENT)
      continue;

    const auto *meta = reinterpret_cast<const evt_le_meta_event *>(
        buf.data() + 1 + HCI_EVENT_HDR_SIZE);
    if (meta->subevent != EVT_LE_ADVERTISING_REPORT)
      continue;

    uint8_t reports = meta->data[0];
    const uint8_t *ptr = meta->data + 1;
    for (uint8_t i = 0; i < reports; ++i) {
      const auto *info = reinterpret_cast<const le_advertising_info *>(ptr);

      Device d;
      char addr[19] = {0};
      ba2str(&info->bdaddr, addr);
      d.address = addr;
      d.ble = true;
      d.name = eir_name(info->data, info->length);
      if (info->length > 0)
        d.rssi = static_cast<int8_t>(info->data[info->length]);
      if (d.name.empty())
        d.name = "(unnamed)";

      out.push_back(std::move(d));
      ptr += sizeof(le_advertising_info) + info->length;
      if (static_cast<int>(out.size()) >= max_dev)
        break;
    }
  }

  hci_le_set_scan_enable(dd, 0x00, 0x00, 1000);
  ::close(dd);

  if (out.empty() && err.empty())
    err = "no advertising reports received";
  return out;
}

PingStats l2ping(const std::string &addr, int size, int count, int timeout_ms) {
  PingStats stats;
  bdaddr_t ba;
  if (str2ba(addr.c_str(), &ba) < 0)
    return stats;

  const int payload = clamp_int(size, 1, kMaxEchoPayload);
  const int probes = clamp_int(count, 1, kMaxEchoCount);

  int sk = socket(AF_BLUETOOTH, SOCK_RAW | SOCK_CLOEXEC, BTPROTO_L2CAP);
  if (sk < 0) {
    stats.error = std::string("l2cap socket: ") + std::strerror(errno);
    LOG_DEBUG(stats.error);
    return stats;
  }

  sockaddr_l2 la{};
  la.l2_family = AF_BLUETOOTH;
  la.l2_bdaddr = ba;
  la.l2_psm = htobs(0x0001);

  if (connect(sk, reinterpret_cast<sockaddr *>(&la), sizeof(la)) < 0) {
    stats.error = std::string("l2cap connect: ") + std::strerror(errno);
    LOG_DEBUG(stats.error);
    ::close(sk);
    return stats;
  }

  const std::vector<uint8_t> body(payload, 0x42);
  double sum = 0.0;

  for (int i = 0; i < probes; ++i) {
    std::vector<uint8_t> pkt(sizeof(L2capHdr) + payload);
    auto *h = reinterpret_cast<L2capHdr *>(pkt.data());
    h->code = kEchoReqCode;
    h->ident = static_cast<uint8_t>(i & 0xff);
    h->len = htobs(static_cast<uint16_t>(payload));
    std::memcpy(pkt.data() + sizeof(L2capHdr), body.data(), body.size());

    double t0 = now_ms();
    if (send(sk, pkt.data(), pkt.size(), 0) < 0) {
      if (stats.error.empty())
        stats.error = std::string("l2cap send: ") + std::strerror(errno);
      continue;
    }
    stats.sent++;

    pollfd pfd{sk, POLLIN, 0};
    if (poll(&pfd, 1, timeout_ms) <= 0)
      continue;

    std::array<uint8_t, 1024> rbuf{};
    ssize_t n = recv(sk, rbuf.data(), rbuf.size(), 0);
    if (n < static_cast<ssize_t>(sizeof(L2capHdr)) ||
        rbuf[0] != kEchoRspCode)
      continue;

    double dt = now_ms() - t0;
    stats.received++;
    sum += dt;
    if (stats.min_ms == 0.0 || dt < stats.min_ms)
      stats.min_ms = dt;
    if (dt > stats.max_ms)
      stats.max_ms = dt;
  }

  ::close(sk);
  stats.avg_ms = stats.received ? sum / stats.received : 0.0;
  return stats;
}

namespace {

/// Connect to one PSM with a real timeout. Returns a blocking socket or -1.
int l2cap_connect_to(const bdaddr_t &ba, uint16_t psm, int timeout_ms,
                     std::string &err) {
  int sk = socket(AF_BLUETOOTH, SOCK_SEQPACKET | SOCK_CLOEXEC, BTPROTO_L2CAP);
  if (sk < 0) {
    err = errtxt("l2cap socket");
    return -1;
  }

  sockaddr_l2 la{};
  la.l2_family = AF_BLUETOOTH;
  la.l2_bdaddr = ba;
  la.l2_psm = htobs(psm);

  const int flags = fcntl(sk, F_GETFL, 0);
  fcntl(sk, F_SETFL, flags | O_NONBLOCK);

  int rc = connect(sk, reinterpret_cast<sockaddr *>(&la), sizeof(la));
  if (rc < 0 && errno != EINPROGRESS) {
    err = errtxt("l2cap connect");
    ::close(sk);
    return -1;
  }

  if (rc < 0) {
    pollfd pfd{sk, POLLOUT, 0};
    int pr = 0;
    do {
      pr = poll(&pfd, 1, timeout_ms);
    } while (pr < 0 && errno == EINTR);
    if (pr <= 0) {
      err = pr == 0 ? "l2cap connect: timed out" : errtxt("l2cap poll");
      ::close(sk);
      return -1;
    }
    int soerr = 0;
    socklen_t len = sizeof(soerr);
    if (getsockopt(sk, SOL_SOCKET, SO_ERROR, &soerr, &len) < 0 || soerr != 0) {
      err = std::string("l2cap connect: ") +
            std::strerror(soerr ? soerr : errno);
      ::close(sk);
      return -1;
    }
  }

  fcntl(sk, F_SETFL, flags);
  return sk;
}

void drain_echo_replies(int sk, int &replied) {
  std::array<uint8_t, 1024> rbuf{};
  for (;;) {
    ssize_t n = recv(sk, rbuf.data(), rbuf.size(), MSG_DONTWAIT);
    if (n <= 0)
      break;
    if (n >= static_cast<ssize_t>(sizeof(L2capHdr)) &&
        rbuf[0] == kEchoRspCode)
      ++replied;
  }
}

} // namespace

int l2cap_echo_burst(const std::string &addr, int payload, int rate_pps,
                     int duration_s, int &replied) {
  replied = 0;
  bdaddr_t ba;
  if (str2ba(addr.c_str(), &ba) < 0)
    return 0;

  const int size = clamp_int(payload, 1, kMaxBurstPayload);
  const int rate = clamp_int(rate_pps, 1, kMaxBurstRate);
  const int duration = clamp_int(duration_s, 1, kMaxBurstDuration);

  int sk = socket(AF_BLUETOOTH, SOCK_RAW | SOCK_CLOEXEC, BTPROTO_L2CAP);
  if (sk < 0) {
    LOG_DEBUG("l2cap burst socket: " << std::strerror(errno));
    return 0;
  }

  sockaddr_l2 la{};
  la.l2_family = AF_BLUETOOTH;
  la.l2_bdaddr = ba;
  la.l2_psm = htobs(0x0001);
  if (connect(sk, reinterpret_cast<sockaddr *>(&la), sizeof(la)) < 0) {
    LOG_DEBUG("l2cap burst connect: " << std::strerror(errno));
    ::close(sk);
    return 0;
  }

  const auto interval = std::chrono::microseconds(1000000 / rate);
  const auto deadline =
      std::chrono::steady_clock::now() + std::chrono::seconds(duration);
  const std::vector<uint8_t> body(static_cast<size_t>(size), 0x42);

  int sent = 0;
  while (std::chrono::steady_clock::now() < deadline) {
    const auto cycle_start = std::chrono::steady_clock::now();

    std::vector<uint8_t> pkt(sizeof(L2capHdr) + body.size());
    auto *h = reinterpret_cast<L2capHdr *>(pkt.data());
    h->code = kEchoReqCode;
    h->ident = static_cast<uint8_t>(sent & 0xff);
    h->len = htobs(static_cast<uint16_t>(body.size()));
    std::memcpy(pkt.data() + sizeof(L2capHdr), body.data(), body.size());

    if (send(sk, pkt.data(), pkt.size(), 0) < 0) {
      LOG_DEBUG("l2cap burst send: " << std::strerror(errno));
      break;
    }
    ++sent;
    drain_echo_replies(sk, replied);

    const auto spent = std::chrono::steady_clock::now() - cycle_start;
    if (spent < interval)
      std::this_thread::sleep_for(interval - spent);
  }

  drain_echo_replies(sk, replied);
  ::close(sk);
  return sent;
}

int l2cap_connect_burst(const std::string &addr, uint16_t psm, int wanted,
                        int hold_s) {
  bdaddr_t ba;
  if (str2ba(addr.c_str(), &ba) < 0)
    return 0;

  const int count = clamp_int(wanted, 1, kMaxBurstConnections);
  const int hold = clamp_int(hold_s, 1, 10);

  std::vector<int> socks;
  socks.reserve(static_cast<size_t>(count));
  for (int i = 0; i < count; ++i) {
    std::string err;
    int sk = l2cap_connect_to(ba, psm, 3000, err);
    if (sk < 0) {
      LOG_DEBUG("burst connection " << (i + 1) << ": " << err);
      break;
    }
    socks.push_back(sk);
  }

  if (!socks.empty())
    std::this_thread::sleep_for(std::chrono::seconds(hold));

  for (int sk : socks)
    ::close(sk);
  return static_cast<int>(socks.size());
}

int l2cap_connect_cycles(const std::string &addr, uint16_t psm, int cycles) {
  bdaddr_t ba;
  if (str2ba(addr.c_str(), &ba) < 0)
    return 0;

  const int total = clamp_int(cycles, 1, kMaxCycleCount);
  int ok = 0;
  for (int i = 0; i < total; ++i) {
    std::string err;
    int sk = l2cap_connect_to(ba, psm, 2000, err);
    if (sk < 0) {
      LOG_DEBUG("cycle " << (i + 1) << ": " << err);
      break;
    }
    ++ok;
    ::close(sk);
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  return ok;
}

bool rfcomm_connect(const std::string &addr, int channel, int timeout_ms,
                    int &sock) {
  sock = -1;
  bdaddr_t ba;
  if (str2ba(addr.c_str(), &ba) < 0)
    return false;

  const int ch = clamp_int(channel, 1, kMaxRfcommChannel);
  const int timeout = clamp_int(timeout_ms, 500, 60000);

  int sk = socket(AF_BLUETOOTH, SOCK_STREAM | SOCK_CLOEXEC, BTPROTO_RFCOMM);
  if (sk < 0) {
    LOG_DEBUG("rfcomm socket: " << std::strerror(errno));
    return false;
  }

  sockaddr_rc rc{};
  rc.rc_family = AF_BLUETOOTH;
  rc.rc_bdaddr = ba;
  rc.rc_channel = static_cast<uint8_t>(ch);

  const int flags = fcntl(sk, F_GETFL, 0);
  fcntl(sk, F_SETFL, flags | O_NONBLOCK);

  int result = connect(sk, reinterpret_cast<sockaddr *>(&rc), sizeof(rc));
  if (result < 0 && errno != EINPROGRESS) {
    LOG_DEBUG("rfcomm connect ch" << ch << ": " << std::strerror(errno));
    ::close(sk);
    return false;
  }

  if (result < 0) {
    pollfd pfd{sk, POLLOUT, 0};
    int pr = 0;
    do {
      pr = poll(&pfd, 1, timeout);
    } while (pr < 0 && errno == EINTR);
    if (pr <= 0) {
      LOG_DEBUG("rfcomm connect ch" << ch << ": timed out");
      ::close(sk);
      return false;
    }
    int soerr = 0;
    socklen_t len = sizeof(soerr);
    if (getsockopt(sk, SOL_SOCKET, SO_ERROR, &soerr, &len) < 0 || soerr != 0) {
      LOG_DEBUG("rfcomm connect ch" << ch << ": "
                                    << std::strerror(soerr ? soerr : errno));
      ::close(sk);
      return false;
    }
  }

  fcntl(sk, F_SETFL, flags);
  sock = sk;
  return true;
}

bool rfcomm_send(int sock, const std::string &data) {
  if (sock < 0 || data.empty())
    return false;
  size_t off = 0;
  while (off < data.size()) {
    ssize_t n = send(sock, data.data() + off, data.size() - off, MSG_NOSIGNAL);
    if (n <= 0) {
      if (errno == EINTR)
        continue;
      LOG_DEBUG("rfcomm send: " << std::strerror(errno));
      return false;
    }
    off += static_cast<size_t>(n);
  }
  return true;
}

std::string rfcomm_read(int sock, int timeout_ms) {
  std::string out;
  if (sock < 0)
    return out;

  const int timeout = clamp_int(timeout_ms, 100, 10000);
  std::array<char, 512> buf{};
  const auto deadline =
      std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout);

  while (std::chrono::steady_clock::now() < deadline && out.size() < 8192) {
    const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(
                          deadline - std::chrono::steady_clock::now())
                          .count();
    pollfd pfd{sock, POLLIN, 0};
    int pr = poll(&pfd, 1, static_cast<int>(std::max<long long>(1, left)));
    if (pr < 0) {
      if (errno == EINTR)
        continue;
      break;
    }
    if (pr == 0)
      continue;
    ssize_t n = recv(sock, buf.data(), buf.size(), 0);
    if (n > 0)
      out.append(buf.data(), static_cast<size_t>(n));
    else
      break;
  }
  return out;
}

ToolResult run_tool(const std::vector<std::string> &argv, int timeout_ms,
                    const std::string &cwd) {
  ToolResult res;
  if (argv.empty())
    return res;

  std::vector<char *> cargv;
  cargv.reserve(argv.size() + 1);
  for (const auto &a : argv)
    cargv.push_back(const_cast<char *>(a.c_str()));
  cargv.push_back(nullptr);

  int fds[2];
  if (pipe2(fds, O_CLOEXEC) < 0) {
    res.output = errtxt("pipe");
    return res;
  }

  pid_t pid = fork();
  if (pid < 0) {
    res.output = errtxt("fork");
    ::close(fds[0]);
    ::close(fds[1]);
    return res;
  }

  if (pid == 0) {
    ::close(fds[0]);
    dup2(fds[1], STDOUT_FILENO);
    dup2(fds[1], STDERR_FILENO);
    ::close(fds[1]);
    if (!cwd.empty() && chdir(cwd.c_str()) < 0)
      _exit(127);
    execvp(cargv[0], cargv.data());
    _exit(127);
  }

  ::close(fds[1]);

  const int budget = clamp_int(timeout_ms, 1000, 120000);
  const auto deadline = std::chrono::steady_clock::now() +
                        std::chrono::milliseconds(budget);
  bool timed_out = false;
  std::array<char, 512> buf{};

  for (;;) {
    const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(
                          deadline - std::chrono::steady_clock::now())
                          .count();
    if (left <= 0) {
      timed_out = true;
      break;
    }
    pollfd pfd{fds[0], POLLIN, 0};
    int pr = poll(&pfd, 1, static_cast<int>(std::min<long long>(left, 500)));
    if (pr < 0) {
      if (errno == EINTR)
        continue;
      break;
    }
    if (pr == 0)
      continue;
    ssize_t n = read(fds[0], buf.data(), buf.size());
    if (n > 0) {
      if (res.output.size() < 65536)
        res.output.append(buf.data(), static_cast<size_t>(n));
    } else if (n == 0) {
      break;
    } else if (errno != EINTR) {
      break;
    }
  }

  ::close(fds[0]);
  if (timed_out)
    kill(pid, SIGKILL);

  int status = 0;
  waitpid(pid, &status, 0);

  if (timed_out)
    res.exit_code = -2;
  else if (WIFEXITED(status))
    res.exit_code = WEXITSTATUS(status);
  else if (WIFSIGNALED(status))
    res.exit_code = -WTERMSIG(status);
  return res;
}

bool tool_exists(const std::string &tool) {
  if (tool.empty())
    return false;
  if (tool.find('/') != std::string::npos)
    return access(tool.c_str(), X_OK) == 0;

  const char *path = std::getenv("PATH");
  if (!path)
    return false;

  std::string list(path);
  size_t start = 0;
  while (start <= list.size()) {
    size_t sep = list.find(':', start);
    std::string dir = list.substr(start, sep == std::string::npos
                                             ? std::string::npos
                                             : sep - start);
    if (dir.empty())
      dir = ".";
    std::error_code ec;
    auto candidate = std::filesystem::path(dir) / tool;
    if (std::filesystem::exists(candidate, ec) && !ec &&
        access(candidate.c_str(), X_OK) == 0)
      return true;
    if (sep == std::string::npos)
      break;
    start = sep + 1;
  }
  return false;
}

std::vector<Service> sdp_services(const std::string &addr, std::string &err) {
  std::vector<Service> out;

  bdaddr_t ba;
  if (str2ba(addr.c_str(), &ba) < 0) {
    err = "invalid BD_ADDR: " + addr;
    return out;
  }

  bdaddr_t any{};
  sdp_session_t *session = sdp_connect(&any, &ba, SDP_RETRY_IF_BUSY);
  if (!session) {
    err = errtxt("SDP connect");
    return out;
  }

  uuid_t browse_group{};
  sdp_uuid16_create(&browse_group, PUBLIC_BROWSE_GROUP);

  sdp_list_t *search = sdp_list_append(nullptr, &browse_group);
  uint32_t attr_range[2] = {0x0000, 0xffff};
  sdp_list_t *attrs = sdp_list_append(nullptr, attr_range);
  sdp_list_t *records = nullptr;

  int rc = sdp_service_search_attr_req(session, search, SDP_ATTR_REQ_RANGE,
                                       attrs, &records);
  sdp_list_free(search, nullptr);
  sdp_list_free(attrs, nullptr);

  if (rc != 0) {
    err = "SDP browse failed (service discovery may be disabled)";
    sdp_close(session);
    return out;
  }

  for (sdp_list_t *it = records; it; it = it->next) {
    auto *rec = static_cast<sdp_record_t *>(it->data);
    if (!rec)
      continue;

    Service svc;
    svc.handle = rec->handle;
    svc.name = record_name(rec);
    if (svc.name.empty())
      svc.name = "(unnamed service)";

    if (const sdp_data_t *classes =
            sdp_data_get(rec, SDP_ATTR_SVCLASS_ID_LIST))
      collect_class_uuids(classes, svc.classes);

    const sdp_data_t *protos = sdp_data_get(rec, SDP_ATTR_PROTO_DESC_LIST);
    if (protos) {
      int channel = proto_port(protos, RFCOMM_UUID);
      int psm = proto_port(protos, L2CAP_UUID);
      if (channel > 0) {
        svc.rfcomm_channel = channel;
        svc.transport = "RFCOMM ch " + std::to_string(channel);
      } else if (psm > 0) {
        svc.l2cap_psm = psm;
        char buf[32];
        std::snprintf(buf, sizeof(buf), "L2CAP PSM 0x%04x", psm);
        svc.transport = buf;
      }
    }

    out.push_back(std::move(svc));
  }

  sdp_list_free(records, reinterpret_cast<sdp_free_func_t>(sdp_record_free));
  sdp_close(session);
  if (out.empty())
    err = "peer returned no SDP records";
  return out;
}

AdapterInfo adapter_info(const std::string &iface) {
  AdapterInfo info;
  int devid = devid_from_iface(iface);
  if (devid < 0) {
    info.error = "adapter not found: " + iface;
    return info;
  }

  int dd = hci_open_dev(devid);
  if (dd < 0) {
    info.error = errtxt("hci_open_dev");
    return info;
  }

  bdaddr_t ba{};
  if (hci_read_bd_addr(dd, &ba, 1000) == 0) {
    char addr[19] = {0};
    ba2str(&ba, addr);
    info.address = addr;
  }

  char name[HCI_MAX_NAME_LENGTH] = {0};
  if (hci_read_local_name(dd, sizeof(name), name, 1000) == 0)
    info.name = name;

  struct hci_version ver {};
  if (hci_read_local_version(dd, &ver, 1000) == 0) {
    info.hci_version = ver.hci_ver;
    info.lmp_version = ver.lmp_ver;
    info.hci_revision = ver.hci_rev;
    const char *vendor = bt_compidtostr(ver.manufacturer);
    if (vendor)
      info.manufacturer = vendor;
  }

  uint8_t features[8] = {0};
  if (hci_read_local_features(dd, features, 1000) == 0) {
    info.le_supported = (features[4] & 0x40) != 0;
    info.secure_simple_pairing = (features[6] & 0x01) != 0;
  }

  uint8_t cls[3] = {0};
  if (hci_read_class_of_dev(dd, cls, 1000) == 0)
    info.dev_class = (static_cast<uint32_t>(cls[0]) << 16) |
                     (static_cast<uint32_t>(cls[1]) << 8) | cls[2];

  uint8_t scan_enable = 0;
  if (read_scan_enable(dd, scan_enable)) {
    info.discoverable = (scan_enable & 0x01) != 0;
    info.connectable = (scan_enable & 0x02) != 0;
  }

  uint8_t ssp = 0;
  if (hci_read_simple_pairing_mode(dd, &ssp, 1000) == 0)
    info.secure_simple_pairing = ssp != 0;

  hci_close_dev(dd);
  return info;
}

std::string profile_name(uint16_t uuid16) {
  switch (uuid16) {
  case 0x1000:
    return "Service Discovery Server";
  case 0x1001:
    return "Browse Group Descriptor";
  case 0x1002:
    return "Public Browse Group";
  case 0x1101:
    return "Serial Port (SPP)";
  case 0x1103:
    return "Dial-up Networking (DUN)";
  case 0x1104:
    return "LAN Access (LAP)";
  case 0x1105:
    return "OBEX Object Push";
  case 0x1106:
    return "OBEX File Transfer";
  case 0x1107:
    return "IRMC Sync";
  case 0x1108:
    return "Headset";
  case 0x1109:
    return "Cordless Telephony";
  case 0x110A:
    return "Audio Source";
  case 0x110B:
    return "Audio Sink";
  case 0x110C:
    return "A/V Remote Control Target";
  case 0x110D:
    return "Advanced Audio Distribution";
  case 0x110E:
    return "A/V Remote Control";
  case 0x110F:
    return "A/V Remote Control Controller";
  case 0x1112:
    return "Headset Audio Gateway";
  case 0x1113:
    return "SIM Access";
  case 0x1115:
    return "PAN User";
  case 0x1116:
    return "PAN Network Access Point";
  case 0x1117:
    return "PAN Group Ad-hoc Network";
  case 0x111E:
    return "Handsfree";
  case 0x111F:
    return "Handsfree Audio Gateway";
  case 0x1124:
    return "Human Interface Device (HID)";
  case 0x112D:
    return "SIM Access Server";
  case 0x112E:
    return "Phonebook Access (PCE)";
  case 0x112F:
    return "Phonebook Access Server (PSE)";
  case 0x1132:
    return "Message Access Server";
  case 0x1200:
    return "PnP Information";
  case 0x1203:
    return "Generic Audio";
  case 0x1204:
    return "Generic Telephony";
  default:
    break;
  }
  char buf[16];
  std::snprintf(buf, sizeof(buf), "0x%04x", uuid16);
  return buf;
}

std::string hci_version_string(int version) {
  return hci_version_name(version);
}

} // namespace blueboy::bt
