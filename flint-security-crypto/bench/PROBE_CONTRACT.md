# flint:security-crypto probe

The fixture builds PasswordEncoderFactories.createDelegatingPasswordEncoder() and matches a raw password against `{noop}koala`, then asks whether that encoding needs an upgrade to the bcrypt default. It prints one line that depends on its arguments: `match upgrade` with none, and `mismatch upgrade` with one.

The baseline in `baseline/` declares the module's direct dependencies (flint:conc, flint:java), but not the module. It prints the same line computed without the module: the operation is omitted, as packages' PROBE_CONTRACT.md allows for a package without a native provider.

`tools/measure_builds.py` takes the larger O3/Oz stripped-size difference as the module's `incremental_linked_bytes`. That is what the module, together with what it pulls in from its dependencies, adds to an application. Template instances count the compiler invocations that compile `security/security-crypto`, the probe included. The budget is in `policy/framework.json` (`tools/framework_budgets.py`).
