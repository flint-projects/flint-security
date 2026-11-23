// Ported from spring-security 7.2.0: core/src/main/java/org/springframework/security/access/prepost
// Copyright 2004-present the original author or authors.
// Licensed under the Apache License, Version 2.0.
// Modified by the Flint authors.

/++
`org.springframework.security.access.prepost`: method authorization by SpEL expressions, which Flint AOT compiles
(contract 3).
+/
module flint.security.access.prepost;

@safe:

/// Authorize a method call before it runs: `@PreAuthorize("hasRole('ADMIN')")`.
struct PreAuthorize
{
    /// The SpEL expression.
    string value;
}

/// Authorize a method's result after it runs: `@PostAuthorize("returnObject.owner == authentication.name")`.
struct PostAuthorize
{
    /// The SpEL expression.
    string value;
}
