# flint:security-web probe

The fixture assembles petclinic-rest's HTTP Basic security filter chain (security context, headers, Basic authentication over a DaoAuthenticationProvider, anonymous, exception translation and authorization) into a FilterChainProxy, without dispatching a request (a servlet request needs flint:framework-test's mocks, a test dependency). It prints one line that depends on its arguments: `Realm 6` with none, and `Petclinic 6` with one.

The baseline in `baseline/` declares the module's direct dependencies (flint:engine-aot, flint:jakarta-servlet, flint:java, flint:security-core), but not the module. It prints the same line computed without the module: the operation is omitted, as packages' PROBE_CONTRACT.md allows for a package without a native provider.

`tools/measure_builds.py` takes the larger O3/Oz stripped-size difference as the module's `incremental_linked_bytes`. That is what the module, together with what it pulls in from its dependencies, adds to an application. Template instances count the compiler invocations that compile `security/security-web`, the probe included. The budget is in `policy/framework.json` (`tools/framework_budgets.py`).
