# multiformats

[multiformat](https://github.com/multiformats/multiformats) implementations in C++


### example

```c++
#include <string>
#include <iostream>
#include "multiformats/multihash/multihash.h"

using namespace std;
using namespace mh = multi::hash;

int main() {
    auto data = "this is some data to hash"s;
    auto    h = mh::New(); 
    /*
    if you call mh::New() with no arguments it defaults 
    to using SHA256.
    */

    h.sum(data);
    cout << h.hex() << endl;

    /*
    If you call mh::New() with a hash function argument, 
    it'll return an std::optional<Hash>, since constructor 
    might fail (i.e. you pass in an argument it doesn't 
    understand). 
    */
    if (auto h2 = mh::New("sha3-224")) {
        h2->sum(data);
        cout << h2->hex() << endl;
    }

    if (auto h3 = mh::New("blake2b-224")) {
        h3->sum(data);
        cout << h3->hex() << endl;
    }

    if (auto h4 = mh::New("apple pie")) {
        h4->sum(data);
        cout << h4->hex() << endl;
    } else {
        cout << "nope" << endl;
    }
}
```
output:
```
1220cc98718f1394ba1071417e108bfb27a81c6fa7ff332ef4e1db37e5df2a9d18f0
171c60370c984ca8fd5fd39842f70acf3605d2c6443bb1cf38a2fc8fd565
9ce4021c49f3a5c43dce55ad6902c2f04e9f78032d7528f58c9f9e4ebf01bb07
nope
```

### requirements

- C++17
- bazel build system
- that's it


### currently implemented:

- [x] multihash
- [ ] multiaddr
- [ ] multibase
- [ ] multistream


### including in your bazel build as a dependency:

just add this to your ```WORKSPACE``` file:

```
http_archive(
     name = "multiformats",
     urls = ["https://github.com/amatuni/multiformats/archive/master.zip"],
     strip_prefix = "multiformats-master",
)
```

then add as dependency to your target:

```
cc_binary(
    name = "my_binary",
    srcs = ["main.cc"],
    copts = [
        "-std=c++1z",
        "-Wall",
        "-Wextra",
    ],
    deps = [
        "@multiformats//multiformats/multihash",
    ],
)
```