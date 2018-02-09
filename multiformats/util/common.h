#pragma once

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