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
    auto    h = mh::New("sha256"); 
    auto data = "this is some data to hash"s;

    h.sum(data);

    cout << h.hex_string() << endl;

}
```
output:
```
1220cc98718f1394ba1071417e108bfb27a81c6fa7ff332ef4e1db37e5df2a9d18f0
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
     urls = ["https://github.com/andreiamatuni/multiformats/archive/master.zip"],
     strip_prefix = "multiformats-master",
)
```