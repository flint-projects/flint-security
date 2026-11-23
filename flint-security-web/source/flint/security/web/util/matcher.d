// Ported from spring-security 7.2.0: web/src/main/java/org/springframework/security/web/util/matcher
// Copyright 2004-present the original author or authors.
// Licensed under the Apache License, Version 2.0.
// Modified by the Flint authors.

/++
`org.springframework.security.web.util.matcher`: request matchers.
+/
module flint.security.web.util.matcher;

import flint.jakarta.servlet.http : HttpServletRequest;

@safe:

/// Matches requests (Spring Security's `RequestMatcher`).
interface RequestMatcher
{
    /// Whether `request` matches.
    bool matches(HttpServletRequest request);
}

/// Matches every request (Spring Security's `AnyRequestMatcher`).
final class AnyRequestMatcher : RequestMatcher
{
    /// The shared instance.
    static RequestMatcher INSTANCE()
    {
        return new AnyRequestMatcher;
    }

    /// True.
    bool matches(HttpServletRequest)
    {
        return true;
    }

    /// `any request`.
    override string toString()
    {
        return "any request";
    }
}

/// Matches by the path within the application and, optionally, the method (Spring Security's
/// `PathPatternRequestMatcher`, for exact paths and a trailing `/**`).
final class PathRequestMatcher : RequestMatcher
{
    private string pattern;
    private string method;

    /// Paths matching `pattern` (`/api/**`, `/health`), with any method or `method`.
    this(string pattern, string method = null)
    {
        this.pattern = pattern;
        this.method = method;
    }

    /// Whether the path (servlet path plus path info) and method match.
    bool matches(HttpServletRequest request)
    {
        if (method !is null && request.getMethod() != method)
            return false;
        const path = request.getServletPath() ~ (request.getPathInfo() is null ? "" : request.getPathInfo());
        if (pattern.length >= 3 && pattern[$ - 3 .. $] == "/**")
        {
            const base = pattern[0 .. $ - 3];
            return path == base || (path.length > base.length && path[0 .. base.length] == base
                    && path[base.length] == '/');
        }
        return path == pattern;
    }
}
