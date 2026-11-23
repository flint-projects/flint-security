# flint:security-config probe

The fixture builds petclinic-rest's BasicAuthenticationConfig filter chain through HttpSecurity (CSRF off, HTTP Basic, an in-memory AuthenticationManagerBuilder) and prints its authorization rule and its number of filters. It prints one line that depends on its arguments: `authenticated 6` with none, and `permitAll 6` with one.

The baseline in `baseline/` declares the module's direct dependencies (flint:beans, flint:context, flint:core, flint:engine-aot, flint:jakarta-servlet, flint:java, flint:security-core, flint:security-crypto, flint:security-web), but not the module. It prints the same line computed without the module: the operation is omitted, as packages' PROBE_CONTRACT.md allows for a package without a native provider.

`tools/measure_builds.py` takes the larger O3/Oz stripped-size difference as the module's `incremental_linked_bytes`. That is what the module, together with what it pulls in from its dependencies, adds to an application. Template instances count the compiler invocations that compile `security/security-config`, the probe included. The budget is in `policy/framework.json` (`tools/framework_budgets.py`).
