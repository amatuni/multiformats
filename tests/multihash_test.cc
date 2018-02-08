#include "multiformats/multihash/multihash.h"
#include "gtest/gtest.h"

using namespace std;
namespace mh = multi::hash;

TEST(MultihashTest, CheckSHA1) {
  auto   h = mh::New("sha1");
  string data("this is some data to hash");
  h.sum(data);
  EXPECT_EQ(h.hex_string(), "8c01cfecb50deb6ddcc39eddbddb012835f7919a");
}

TEST(MultihashTest, CheckSHA2_256) {
  auto   h = mh::New("sha256");
  string data("this is some data to hash");
  h.sum(data);
  EXPECT_EQ(h.hex_string(),
            "cc98718f1394ba1071417e108bfb27a81c6fa7ff332ef4e1db37e5df2a9d18f0");
}

TEST(MultihashTest, CheckSHA2_512) {
  auto   h = mh::New("sha2-512");
  string data("this is some data to hash");
  h.sum(data);
  EXPECT_EQ(h.hex_string(),
            "a47a2a38acdd9addde6b90e8fb3dc5e6a83bb38babfa0167ceaed8e57bade03c8b"
            "1b2ea53776cf2d1c0f5ee3241511e9eabc14f868c4ac63a35e9879ac1977f6");
}