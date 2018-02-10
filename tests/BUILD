load("//multiformats:multiformats.bzl", "COPTS")

cc_binary(
    name = "mh_test",
    srcs = ["main.cc"],
    copts = COPTS,
    deps = [
        "//multiformats/multihash",
        "//multiformats/util",
        "//third_party:crypto",
    ],
)

cc_test(
    name = "multihash_test",
    srcs = ["multihash_test.cc"],
    copts = [
        "-Iexternal/gtest/include",
    ] + COPTS,
    deps = [
        "//multiformats/multihash",
        "@gtest//:main",
    ],
)
