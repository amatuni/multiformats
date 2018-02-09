load("//multiformats:multiformats.bzl", "COPTS")

cc_library(
    name = "multihash",
    srcs = [
        "multihash.cc",
        "multihash.h",
    ],
    hdrs = glob(["*.h"]),
    copts = COPTS,
    visibility = ["//visibility:public"],
    deps = [
        "//multiformats/util",
        "//third_party:crypto",
        "//third_party:strutils",
    ],
)
