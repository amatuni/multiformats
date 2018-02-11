#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "multiformats/util/common.h"
#include "multiformats/util/varint.h"

#include "third_party/crypto/blake2.h"
#include "third_party/crypto/keccak-tiny.h"
// #include "third_party/crypto/keccak.h"
#include "third_party/crypto/sha1.h"
#include "third_party/crypto/sha256.h"
#include "third_party/crypto/sha512.h"

#include "third_party/strutils/tinyformat.h"
#include "third_party/strutils/utilstrencodings.h"

namespace multi::hash {

using namespace std;
using namespace multi;

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
  /*
  Construct a new Hash object using SHA256 function.
  */
  static Hash New();
  /*
  Construct a new Hash object using the hash function specified
  as argument. If New() doesn't recognize the hashing function
  you pass in, it will return an empty std::optional.
  */
  static optional<Hash> New(const string& hfunc);
  /*
  Construct a new Hash object, with initial data that needs to
  be digested and a hash function specified as argument. If New()
  doesn't recognize the hashing function you pass in, it will
  return an empty std::optional.
  */
  static optional<Hash> New(const string& data, const string& hfunc);
  /*
  Decode a raw sum into a Hash object. This may fail, returning
  an empty std::optional.
  */
  static optional<Hash> Decode(const vector<uint8_t>& raw_sum);
  /*
  Decode a hex encoded string into a Hash object. This may fail,
  returning an empty std::optional.
  */
  static optional<Hash> DecodeHex(const string& hex_digest);

  /*
  Compute the multihash sum for the data passed as input.
  */
  void sum(const string& data);
  /*
  Return a string with the hex encoded value of the multihash.
  This requires a previous call to sum() or that the object was
  constructed with initial data passed as input.
  */
  string hex_string() const;
  /*
  Return a string with the base 58 encoded value of the multihash.
  This requires a previous call to sum() or that the object was
  constructed with initial data passed as input.
  */
  string b58_string() const;
  /*
  Return a vector of bytes containing the raw value of the multihash.
  This requires a previous call to sum() or that the object was
  constructed with initial data passed as input.
  */
  vector<uint8_t> raw_sum() const;
  /*
  Return the name of the hash function being used for this
  Hash object
  */
  string hash_func_name() const;

  inline static bool initialized = false;

  friend bool operator==(const Hash& lhs, const Hash& rhs);

 private:
  Hash() = delete;
  Hash(string hfunc);
  Hash(HFuncCode code);
  Hash(const string& data, HFuncCode code);
  Hash(uint64_t code, size_t code_len, uint64_t len, size_t len_len,
       const vector<uint8_t>& raw_sum);

  void _prep_sum_buffer(HFuncCode func);

  HFuncCode       _hfunc;
  vector<uint8_t> _sum;
  vector<uint8_t> _code_prefix;
  vector<uint8_t> _size_prefix;
  uint8_t         _prefix_len;
};

bool operator==(const Hash& lhs, const Hash& rhs);

/*
Return a new Hash object. If not provided any arguments,
it will default to using SHA-256 as its hashing function.
*/
Hash New();
/*
Return a new Hash object, initialized with a hashing function
passed as argument.
*/
optional<Hash> New(const string& hfunc);
/*
Return a new Hash object, given initial data to compute the sum
for, and a specified hash function.
*/
optional<Hash> New(const string& data, const string& hfunc);
/*
Parse a Hash object given a raw digest. This can fail if given
malformed input, returning an empty optional<>
*/
optional<Hash> Decode(const vector<uint8_t>& raw_sum);
/*
Parse a Hash object given a hexadecimal string. This can fail
if given malformed input, returning an empty optional<>
*/
optional<Hash> DecodeHex(const string& hex_digest);

optional<HFuncCode> check_and_init(const string& hfunc);

namespace {

void _init();

void sum_sha1(const string& data, vector<uint8_t>& out, uint16_t _prefix_len);
void sum_sha256(const string& data, vector<uint8_t>& out, uint16_t _prefix_len);
void sum_sha512(const string& data, vector<uint8_t>& out, uint16_t _prefix_len);
void sum_sha3_224(const string& data, vector<uint8_t>& out,
                  uint16_t _prefix_len);
void sum_sha3_256(const string& data, vector<uint8_t>& out,
                  uint16_t _prefix_len);
void sum_sha3_384(const string& data, vector<uint8_t>& out,
                  uint16_t _prefix_len);
void sum_sha3_512(const string& data, vector<uint8_t>& out,
                  uint16_t _prefix_len);
void sum_keccak256(const string& data, vector<uint8_t>& out,
                   uint16_t _prefix_len);
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