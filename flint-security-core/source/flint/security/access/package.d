// Ported from spring-security 7.2.0: core/src/main/java/org/springframework/security/access/AccessDeniedException.java
// Copyright 2004-present the original author or authors.
// Licensed under the Apache License, Version 2.0.
// Modified by the Flint authors.

/++
`org.springframework.security.access`: access-denied failures.
+/
module flint.security.access;

import flint.java.lang : RuntimeException;

@safe:

/// Thrown when an authenticated principal lacks permission (Spring Security's `AccessDeniedException`).
class AccessDeniedException : RuntimeException
{
    /// A failure with `message`.
    this(string message, Throwable cause = null, string file = __FILE__, size_t line = __LINE__) pure nothrow
    {
        super(message, cause, file, line);
    }
}
