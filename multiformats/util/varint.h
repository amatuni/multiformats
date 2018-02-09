#pragma once

#include <cstdint>
#include <vector>

namespace multi::varint {

std::vector<uint8_t>  encode(uint64_t);
std::vector<uint64_t> decode(std::vector<uint8_t>& in);

}  // namespace multi::varint