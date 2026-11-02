#include "calculator.h"
#include "generated_flag.h"

namespace lima_fixture {

/// Uses the generated header's define to prove the build-tree include
/// path resolves through the verified-package view.
int parser_value() {
#ifdef LIMA_FIXTURE_GENERATED
    return add(LIMA_FIXTURE_GENERATED, 41);
#else
    return 0;
#endif
}

}  // namespace lima_fixture
