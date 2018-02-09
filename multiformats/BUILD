load("//multiformats:multiformats.bzl", "COPTS")

cc_library(
    name = "multiformats",
    copts = COPTS,
    includes = ["."],
    visibility = ["//visibility:public"],
    deps = [
        ":multihash",
        ":util",
    ],
)
