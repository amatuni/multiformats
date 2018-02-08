#include "varint.h"

namespace multi::varint {
std::vector<uint8_t> encode(uint64_t in) {
  std::vector<uint8_t> out;
  while (in > 127) {
    out.push_back(in | 0x80);
    in >>= 7;
  }
  out.push_back(in);
  return out;
}

uint64_t decode(std::vector<uint8_t> in) {}
}  // namespace multi::varint
