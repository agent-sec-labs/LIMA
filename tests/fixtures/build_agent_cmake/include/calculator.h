#pragma once

namespace lima_fixture {

/// Adds two integers. Used by the E2E fixture to prove the include
/// path from the verified-package view resolves real headers.
int add(int a, int b);

/// Parses a signed integer from a decimal string.
/// Returns 0 on malformed input (fixture-only semantics).
int parse_int(const char *text);

}  // namespace lima_fixture
