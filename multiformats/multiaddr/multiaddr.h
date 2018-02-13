#pragma once

#include <cstdint>

namespace multi::addr {

using namespace std;
using namespace multi;

enum class AddrCode : uint64_t {
  P_IP4   = 0x0004,
  P_TCP   = 0x0006,
  P_UDP   = 0x0111,
  P_DCCP  = 0x0021,
  P_IP6   = 0x0029,
  P_QUIC  = 0x01CC,
  P_SCTP  = 0x0084,
  P_UDT   = 0x012D,
  P_UTP   = 0x012E,
  P_UNIX  = 0x0190,
  P_IPFS  = 0x01A5,
  P_HTTP  = 0x01E0,
  P_HTTPS = 0x01BB,
  P_ONION = 0x01BC
};

class Address {};
}  // namespace multi::addr