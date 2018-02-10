#pragma once

#include <cstdint>
#include <vector>

namespace multi::varint {

/*
Encode a uint64_t into a varint
*/
std::vector<uint8_t> encode(uint64_t);

/*
Parse the first varint in a buffer passed as input.

decode will return the value of the varint as uint64_t
along with the number of bytes processed, in a std::pair<>.

If an error occurs, the returned value is 0 and the number
of bytes processed is <= 0:

    n == 0: buffer too small
    n  < 0: value larger than 64 bits
*/
std::pair<uint64_t, size_t> decode(std::vector<uint8_t>::const_iterator curr,
                                   std::vector<uint8_t>::const_iterator end);

}  // namespace multi::varint