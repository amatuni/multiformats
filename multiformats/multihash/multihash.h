#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <experimental/optional>
#include <iostream>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "multiformats/varint/varint.h"

#include "third_party/crypto/blake2.h"
#include "third_party/crypto/sha1.h"
#include "third_party/crypto/sha256.h"
#include "third_party/crypto/sha512.h"

#include "third_party/strutils/tinyformat.h"
#include "third_party/strutils/utilstrencodings.h"

#ifdef __has_include
#if __has_include(<optional>)
#include <optional>
#define STD_OPTIONAL
#elif __has_include(<experimental/optional>)
#include <experimental/optional>
using std::experimental::optional;
#define EXP_OPTIONAL
#else
#error "Missing <optional>"
#endif
#endif

namespace multi::hash {

using namespace std;

enum class HFuncCode : uint64_t {
  ID         = 0x00,
  SHA1       = 0x11,
  SHA2_256   = 0x12,
  SHA2_512   = 0x13,
  SHA3_224   = 0x17,
  SHA3_256   = 0x16,
  SHA3_384   = 0x15,
  SHA3_512   = 0x14,
  SHA3       = SHA3_512,
  KECCAK_224 = 0x1A,
  KECCAK_256 = 0x1B,
  KECCAK_384 = 0x1C,
  KECCAK_512 = 0x1D,

  SHAKE_128 = 0x18,
  SHAKE_256 = 0x19,

  BLAKE2B_MIN = 0xb201,
  BLAKE2B_MAX = 0xb240,
  BLAKE2S_MIN = 0xb241,
  BLAKE2S_MAX = 0xb260,

  DBL_SHA2_256 = 0x56,

  MURMUR3_128 = 0x22,
  MURMUR3_32  = 0x23,
};

class Hash {
 public:
  static Hash New();
  static Hash New(const string& hfunc);
  static Hash New(const string& data, const string& hfunc);

  static Hash Decode(const vector<uint8_t> raw_sum);
  static Hash Decode(const string& hex_digest);

  void                  sum(const string& data);
  string                hex_string() const;
  string                b58_string() const;
  vector<unsigned char> raw_sum() const;
  string                hash_func_name() const;

  friend bool operator==(const Hash& lhs, const Hash& rhs);

 private:
  Hash() = delete;
  Hash(string hfunc);
  Hash(HFuncCode code);
  Hash(const string& data, HFuncCode code);

  void _prep_sum_buffer(HFuncCode func);

  HFuncCode       _hfunc;
  string          _hfunc_name;
  vector<uint8_t> _sum;
  vector<uint8_t> _code_prefix;
  vector<uint8_t> _size_prefix;
  uint16_t        _prefix_len;
};

bool operator==(const Hash& lhs, const Hash& rhs);

Hash New();                     // default to sha256
Hash New(const string& hfunc);  // construct new hasher given a hashing function
Hash New(const string& data,
         const string& hfunc);  // given data and hashing function

Hash Decode(const vector<uint8_t>& raw_sum);  // parse multihash from sum
Hash Decode(const string& hex_digest);        // parse multihash from hex

optional<HFuncCode> check_and_init(const string& hfunc);

namespace {

void _init();
void sum_sha1(const string& data, vector<uint8_t>& out, uint16_t _prefix_len);
void sum_sha256(const string& data, vector<uint8_t>& out, uint16_t _prefix_len);
void sum_sha512(const string& data, vector<uint8_t>& out, uint16_t _prefix_len);
void sum_blake2b(const string& data, vector<uint8_t>& out,
                 uint16_t _prefix_len);
void sum_murmur3_32(const string& data, vector<uint8_t>& out,
                    uint16_t _prefix_len);

map<HFuncCode, int> default_lengths = {{HFuncCode::ID, -1},
                                       {HFuncCode::SHA1, 20},
                                       {HFuncCode::SHA2_256, 32},
                                       {HFuncCode::SHA2_512, 64},
                                       {HFuncCode::SHA3_224, 28},
                                       {HFuncCode::SHA3_256, 32},
                                       {HFuncCode::SHA3_384, 48},
                                       {HFuncCode::SHA3_512, 64},
                                       {HFuncCode::DBL_SHA2_256, 32},
                                       {HFuncCode::KECCAK_224, 28},
                                       {HFuncCode::KECCAK_256, 32},
                                       {HFuncCode::MURMUR3_32, 4},
                                       {HFuncCode::KECCAK_384, 48},
                                       {HFuncCode::KECCAK_512, 64},
                                       {HFuncCode::SHAKE_128, 32},
                                       {HFuncCode::SHAKE_256, 64}

};

map<string, HFuncCode> code_map = {{"sha1", HFuncCode::SHA1},
                                   {"sha256", HFuncCode::SHA2_256},
                                   {"sha2-256", HFuncCode::SHA2_256},
                                   {"sha2-512", HFuncCode::SHA2_512},
                                   {"sha3", HFuncCode::SHA3_512},
                                   {"sha3-224", HFuncCode::SHA3_224},
                                   {"sha3-256", HFuncCode::SHA3_256},
                                   {"sha3-384", HFuncCode::SHA3_384},
                                   {"sha3-512", HFuncCode::SHA3_512},
                                   {"dbl-sha2-256", HFuncCode::DBL_SHA2_256},
                                   {"murmur3", HFuncCode::MURMUR3_32},
                                   {"keccak-224", HFuncCode::KECCAK_224},
                                   {"keccak-256", HFuncCode::KECCAK_256},
                                   {"keccak-384", HFuncCode::KECCAK_384},
                                   {"keccak-512", HFuncCode::KECCAK_512},
                                   {"shake-128", HFuncCode::SHAKE_128},
                                   {"shake-256", HFuncCode::SHAKE_256}};

map<HFuncCode, string> code_names = {{HFuncCode::SHA1, "sha1"},
                                     {HFuncCode::SHA2_256, "sha2-256"},
                                     {HFuncCode::SHA2_512, "sha2-512"},
                                     {HFuncCode::SHA3_512, "sha3"},
                                     {HFuncCode::SHA3_224, "sha3-224"},
                                     {HFuncCode::SHA3_256, "sha3-256"},
                                     {HFuncCode::SHA3_384, "sha3-384"},
                                     {HFuncCode::SHA3_512, "sha3-512"},
                                     {HFuncCode::DBL_SHA2_256, "dbl-sha2-256"},
                                     {HFuncCode::MURMUR3_32, "murmur3"},
                                     {HFuncCode::KECCAK_224, "keccak-224"},
                                     {HFuncCode::KECCAK_256, "keccak-256"},
                                     {HFuncCode::KECCAK_384, "keccak-384"},
                                     {HFuncCode::KECCAK_512, "keccak-512"},
                                     {HFuncCode::SHAKE_128, "shake-128"},
                                     {HFuncCode::SHAKE_256, "shake-256"}};

}  // namespace
}  // namespace multi::hash