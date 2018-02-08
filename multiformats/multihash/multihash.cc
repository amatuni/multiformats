#include "multihash.h"

namespace multi::hash {

Hash Hash::New() {
  return Hash(HFuncCode::SHA2_256);
}

Hash Hash::New(const string& hfunc) {
  if (auto x = check_and_init(hfunc); x) {
    return Hash(*x);
  }
  return Hash(HFuncCode::SHA2_256);
}

Hash Hash::New(const string& data, const string& hfunc) {
  if (auto x = check_and_init(hfunc); x) {
    return Hash(data, *x);
  }
  return Hash(HFuncCode::SHA2_256);
}

Hash::Hash(const string& data, HFuncCode func) : _hfunc(func) {
  _prep_sum_buffer(func);
  sum(data);
}

Hash::Hash(HFuncCode func) : _hfunc(func) {
  _prep_sum_buffer(func);
}

void Hash::_prep_sum_buffer(HFuncCode func) {
  auto hfc     = static_cast<underlying_type_t<HFuncCode>>(func);
  auto hfl     = default_lengths[func];
  _code_prefix = multi::varint::encode(hfc);
  _size_prefix = multi::varint::encode(hfl);
  _prefix_len  = _code_prefix.size() + _size_prefix.size();

  _sum.resize(_prefix_len + hfl);
  copy(_code_prefix.begin(), _code_prefix.end(), _sum.begin());
  copy(_size_prefix.begin(), _size_prefix.end(),
       _sum.begin() + _code_prefix.size());
}

void Hash::sum(const string& data) {
  // compute hash digest
  switch (_hfunc) {
    case HFuncCode::SHA1:
      sum_sha1(data, _sum, _prefix_len);
      break;
    case HFuncCode::SHA2_256:
      sum_sha256(data, _sum, _prefix_len);
      break;
    case HFuncCode::SHA2_512:
      sum_sha512(data, _sum, _prefix_len);
      break;
    case HFuncCode::BLAKE2B_MIN:
      sum_blake2b(data, _sum, _prefix_len);
      break;
    case HFuncCode::MURMUR3_32:
      sum_murmur3_32(data, _sum, _prefix_len);
      break;
  }
}

string Hash::hex_string() const {
  return HexStr(_sum);
}

vector<unsigned char> Hash::raw_sum() const {
  return _sum;
}

string Hash::hash_func_name() const {
  return code_names[_hfunc];
}

optional<HFuncCode> check_and_init(const string& hfunc) {
  if (auto it = code_map.find(hfunc); it != code_map.end()) {
    _init();
    return it->second;
  }
  return {};
}

Hash New(const string& hfunc) {
  if (auto x = check_and_init(hfunc); x) {
    return Hash::New(hfunc);
  }
  return Hash::New("sha256");
}

Hash Decode(const string& hex_digest) {}

Hash New(const string& data, const string& hfunc) {
  if (auto x = check_and_init(hfunc); x) {
    return Hash::New(data, hfunc);
  }
  return Hash::New("sha256");
}

bool operator==(const Hash& lhs, const Hash& rhs) {
  return lhs._sum == rhs._sum;
}

namespace {
void _init() {
  // generate all the blake2b names
  auto min = static_cast<underlying_type_t<HFuncCode>>(HFuncCode::BLAKE2B_MIN);
  auto max = static_cast<underlying_type_t<HFuncCode>>(HFuncCode::BLAKE2B_MAX);
  for (auto c = min; c <= max; c++) {
    auto hfunc_code             = static_cast<HFuncCode>(c);
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
    auto hfunc_code             = static_cast<HFuncCode>(c);
    auto n                      = c - min + 1;
    auto name                   = tfm::format("blake2s-%d", n * 8);
    default_lengths[hfunc_code] = n;
    code_map[name]              = hfunc_code;
    code_names[hfunc_code]      = name;
  }
}

void sum_sha1(const string& data, vector<unsigned char>& out,
              uint16_t _prefix_len) {
  CSHA1 sha1;
  sha1.Write((unsigned char*)&data[0], data.size()).Finalize(&out[_prefix_len]);
}

void sum_sha256(const string& data, vector<unsigned char>& out,
                uint16_t _prefix_len) {
  CSHA256 sha256;
  sha256.Write((unsigned char*)&data[0], data.size())
      .Finalize(&out[_prefix_len]);
}

void sum_sha512(const string& data, vector<unsigned char>& out,
                uint16_t _prefix_len) {
  CSHA512 sha512;
  sha512.Write((unsigned char*)&data[0], data.size())
      .Finalize(&out[_prefix_len]);
}

void sum_blake2b(const string& data, vector<unsigned char>& out,
                 uint16_t _prefix_len) {
  CSHA512 sha512;
  sha512.Write((unsigned char*)&data[0], data.size())
      .Finalize(&out[_prefix_len]);
}

void sum_murmur3_32(const string& data, vector<unsigned char>& out,
                    uint16_t _prefix_len) {
  CSHA512 sha512;
  sha512.Write((unsigned char*)&data[0], data.size())
      .Finalize(&out[_prefix_len]);
}

}  // namespace
}  // namespace multi::hash