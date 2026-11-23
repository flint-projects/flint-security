# flint:security-core probe

The fixture authenticates a username and password through a ProviderManager over a DaoAuthenticationProvider and an InMemoryUserDetailsManager, and prints the authenticated name and its number of authorities. It prints one line that depends on its arguments: `rod 2` with none, and `joe 1` with one.

The baseline in `baseline/` declares the module's direct dependencies (flint:beans, flint:context, flint:core, flint:engine-aot, flint:engine-reactor, flint:java, flint:jdbc, flint:security-crypto), but not the module. It prints the same line computed without the module: the operation is omitted, as packages' PROBE_CONTRACT.md allows for a package without a native provider.

`tools/measure_builds.py` takes the larger O3/Oz stripped-size difference as the module's `incremental_linked_bytes`. That is what the module, together with what it pulls in from its dependencies, adds to an application. Template instances count the compiler invocations that compile `security/security-core`, the probe included. The budget is in `policy/framework.json` (`tools/framework_budgets.py`).
