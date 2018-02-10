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

// adapted from Go standard library implementation
std::pair<uint64_t, size_t> decode(std::vector<uint8_t>::const_iterator curr,
                                   std::vector<uint8_t>::const_iterator end) {
  uint64_t x = 0;
  uint8_t  s = 0;
  for (size_t i = 0; curr != end; i++) {
    if (*curr < 0x80) {
      if (i > 9 || ((i == 9) && (*curr > 1))) {
        return std::make_pair(0, -(i + 1));  // overflow
      }
      return std::make_pair(x | *curr << s, i + 1);
    }
    x |= (*curr & 0x7f) << s;
    s += 7;
    curr++;
  }
  return std::make_pair(0, 0);
}

}  // namespace multi::varint
