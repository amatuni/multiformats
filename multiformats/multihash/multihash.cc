#include "multihash.h"

namespace multi::hash {

Hash Hash::New() {
  return Hash(HFuncCode::SHA2_256);
}

optional<Hash> Hash::New(const string& hfunc) {
  if (auto x = check_and_init(hfunc); x) {
    return Hash(*x);
  }
  return {};
}

optional<Hash> Hash::New(const string& data, const string& hfunc) {
  if (auto x = check_and_init(hfunc); x) {
    return Hash(data, *x);
  }
  return {};
}

Hash::Hash(const string& data, HFuncCode func) : _hfunc(func) {
  set_hasher(func);
  _prep_sum_buffer(func);
  sum(data);
}

Hash::Hash(HFuncCode func) : _hfunc(func) {
  set_hasher(func);
  _prep_sum_buffer(func);
}

Hash::Hash(uint64_t code, size_t code_len, uint64_t len, size_t len_len,
           const vector<uint8_t>& raw_sum): 
           _sum(raw_sum),
           _hfunc(HFuncCode{code}), 
           _prefix_len(code_len + len_len) {
  set_hasher(_hfunc);
}

void Hash::_prep_sum_buffer(HFuncCode func) {
  auto hfc     = static_cast<underlying_type_t<HFuncCode>>(func);
  auto hfl     = internal::default_lengths[func];
  _code_prefix = multi::varint::encode(hfc);
  _size_prefix = multi::varint::encode(hfl);
  _prefix_len  = _code_prefix.size() + _size_prefix.size();

  _sum.resize(_prefix_len + hfl);
  copy(_code_prefix.begin(), _code_prefix.end(), _sum.begin());
  copy(_size_prefix.begin(), _size_prefix.end(),
       _sum.begin() + _code_prefix.size());
}

optional<Hash> Hash::Decode(const vector<uint8_t>& raw_sum) {
  // need at least 3 bytes
  if (raw_sum.size() < 3) return {};
  // decode the hash function prefix
  auto [code, c_len] = varint::decode(raw_sum.cbegin(), raw_sum.cend());
  // check if that code is legit, if not return empty optional
  if (auto it = internal::code_names.find(HFuncCode{code});
      it == internal::code_names.end()) {
    return {};
  }
  // decode the digest length prefix
  auto [len, l_len] =
      varint::decode((raw_sum.cbegin() + c_len), raw_sum.cend());
  // check if the length is correct with default_lengths lookup
  if (auto def_len = internal::default_lengths.find(HFuncCode{code});
      def_len->second != len) {
    return {};
  }
  return Hash::Hash(code, c_len, len, l_len, raw_sum);
}

optional<Hash> Hash::DecodeHex(const string& hex_digest) {
  vector<uint8_t> raw_sum = ParseHex(hex_digest);
  return Decode(raw_sum);
}

void Hash::sum(const string& data) {
  /*
  the blake functions are self-handling by
  virtue of their length
  */
  if (is_blake2b(_hfunc)) {
    internal::sum_blake2b(data, _sum, _prefix_len);
    return;
  } else if (is_blake2s(_hfunc)) {
    internal::sum_blake2s(data, _sum, _prefix_len);
    return;
  }
  // handle the rest of them
  switch (_hfunc) {
    case HFuncCode::SHA1:
      internal::sum_sha1(&sha1, data, _sum, _prefix_len);
      break;
    case HFuncCode::SHA2_256:
      internal::sum_sha256(&sha256, data, _sum, _prefix_len);
      break;
    case HFuncCode::DBL_SHA2_256:
      internal::sum_dbl_sha256(&sha256, data, _sum, _prefix_len);
      break;
    case HFuncCode::SHA2_512:
      internal::sum_sha512(&sha512, data, _sum, _prefix_len);
      break;
    case HFuncCode::SHA3_224:
      internal::sum_sha3_224(data, _sum, _prefix_len);
      break;
    case HFuncCode::SHA3_256:
      internal::sum_sha3_256(data, _sum, _prefix_len);
      break;
    case HFuncCode::SHA3_384:
      internal::sum_sha3_384(data, _sum, _prefix_len);
      break;
    case HFuncCode::SHA3_512:
      internal::sum_sha3_512(data, _sum, _prefix_len);
      break;
    case HFuncCode::MURMUR3_32:
      internal::sum_murmur3_32(data, _sum, _prefix_len);
      break;
  }
}

string Hash::hex() const {
  return HexStr(_sum);
}

string Hash::b64() const {
  return EncodeBase64(_sum.data(), _sum.size());
}

string Hash::prefix_hex() const {
  return HexStr(_sum.begin(), _sum.begin() + _prefix_len);
}

string Hash::digest_hex() const {
  return HexStr(_sum.cbegin() + _prefix_len, _sum.cend());
}

vector<uint8_t> Hash::raw_sum() const {
  return _sum;
}

string Hash::hash_func_name() const {
  return internal::code_names[_hfunc];
}

void Hash::set_hasher(HFuncCode func) {
  switch (func) {
    case HFuncCode::SHA1:
      sha1 = CSHA1();
      return;
    case HFuncCode::SHA2_256:
      sha256 = CSHA256();
      return;
    case HFuncCode::SHA2_512:
      sha512 = CSHA512();
      return;
  }
}

optional<HFuncCode> check_and_init(const string& hfunc) {
  if (!Hash::initialized) internal::_init();
  if (auto it = internal::code_map.find(hfunc);
      it != internal::code_map.end()) {
    return it->second;
  }
  return {};
}

optional<Hash> New(const string& hfunc) {
  if (auto x = check_and_init(hfunc); x) {
    return Hash::New(hfunc);
  }
  return {};
}

optional<Hash> DecodeHex(const string& hex_digest) {
  return Hash::DecodeHex(hex_digest);
}

optional<Hash> Decode(const vector<uint8_t>& raw_sum) {
  return Hash::Decode(raw_sum);
}

optional<Hash> New(const string& data, const string& hfunc) {
  if (auto x = check_and_init(hfunc); x) {
    return Hash::New(data, hfunc);
  }
  return {};
}

bool operator==(const Hash& lhs, const Hash& rhs) {
  return lhs._sum == rhs._sum;
}

namespace internal {

void _init() {
  // generate all the blake2b names
  auto min = static_cast<underlying_type_t<HFuncCode>>(HFuncCode::BLAKE2B_MIN);
  auto max = static_cast<underlying_type_t<HFuncCode>>(HFuncCode::BLAKE2B_MAX);
  for (auto c = min; c <= max; c++) {
    auto hfunc_code             = HFuncCode{c};
    auto n                      = c - min + 1;
    auto name                   = tfm::format("blake2b-%d", n * 8);
    default_lengths[hfunc_code] = n;
    code_map[name]              = hfunc_code;
    code_names[hfunc_code]      = name;
  }
  // generate all the blake2s names
  min = static_cast<underlying_type_t<HFuncCode>>(HFuncCode::BLAKE2S_MIN);
  max = static_cast<underlying_type_t<HFuncCode>>(HFuncCode::BLAKE2S_MAX);
  for (auto c = min; c <= max; c++) {
    auto hfunc_code             = HFuncCode{c};
    auto n                      = c - min + 1;
    auto name                   = tfm::format("blake2s-%d", n * 8);
    default_lengths[hfunc_code] = n;
    code_map[name]              = hfunc_code;
    code_names[hfunc_code]      = name;
  }
  Hash::initialized = true;
}

inline void sum_sha1(CSHA1* hasher, const string& data, vector<uint8_t>& out,
              uint16_t _prefix_len) {
  hasher->Reset();
  hasher->Write((unsigned char*)&data[0], data.size())
      .Finalize(&out[_prefix_len]);
}

inline void sum_sha256(CSHA256* hasher, const string& data, vector<uint8_t>& out,
                uint16_t _prefix_len) {
  hasher->Reset();
  hasher->Write((unsigned char*)&data[0], data.size())
      .Finalize(&out[_prefix_len]);
}

inline void sum_dbl_sha256(CSHA256* hasher, const string& data, vector<uint8_t>& out,
                    uint16_t _prefix_len) {
  hasher->Reset();
  hasher->Write((unsigned char*)&data[0], data.size())
      .Finalize(&out[_prefix_len]);
  hasher->Reset();
  hasher->Write((unsigned char*)&out[_prefix_len], out.size() - _prefix_len)
      .Finalize(&out[_prefix_len]);
}

inline void sum_sha512(CSHA512* hasher, const string& data, vector<uint8_t>& out,
                uint16_t _prefix_len) {
  hasher->Write((unsigned char*)&data[0], data.size())
      .Finalize(&out[_prefix_len]);
}

inline void sum_sha3_224(const string& data, vector<uint8_t>& out,
                  uint16_t _prefix_len) {
  sha3_224(&out[_prefix_len], out.size() - _prefix_len,
           (const uint8_t*)data.data(), data.size());
}

inline void sum_sha3_256(const string& data, vector<uint8_t>& out,
                  uint16_t _prefix_len) {
  sha3_256(&out[_prefix_len], out.size() - _prefix_len,
           (const uint8_t*)data.data(), data.size());
}

inline void sum_sha3_384(const string& data, vector<uint8_t>& out,
                  uint16_t _prefix_len) {
  sha3_384(&out[_prefix_len], out.size() - _prefix_len,
           (const uint8_t*)data.data(), data.size());
}

inline void sum_sha3_512(const string& data, vector<uint8_t>& out,
                  uint16_t _prefix_len) {
  sha3_512(&out[_prefix_len], out.size() - _prefix_len,
           (const uint8_t*)data.data(), data.size());
}

inline void sum_blake2b(const string& data, vector<uint8_t>& out,
                 uint16_t _prefix_len) {
  blake2b(&out[_prefix_len], out.size() - _prefix_len, data.data(), data.size(),
          (void*)0, 0);
}

inline void sum_blake2s(const string& data, vector<uint8_t>& out,
                 uint16_t _prefix_len) {
  blake2s(&out[_prefix_len], out.size() - _prefix_len, data.data(), data.size(),
          (void*)0, 0);
}

inline void sum_murmur3_32(const string& data, vector<unsigned char>& out,
                    uint16_t _prefix_len) {
  CSHA512 sha512;
  sha512.Write((unsigned char*)&data[0], data.size())
      .Finalize(&out[_prefix_len]);
}

}  // namespace internal
}  // namespace multi::hash