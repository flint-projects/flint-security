// Ported from spring-security 7.2.0: web/src/main/java/org/springframework/security/web/csrf/CsrfFilter.java
// Copyright 2004-present the original author or authors.
// Licensed under the Apache License, Version 2.0.
// Modified by the Flint authors.
/*
 * The token repositories (session and cookie) are not ported, so no request can carry a valid token: a request with
 * an unsafe method is denied through the access-denied handler, as Spring denies one without a token. Applications
 * that accept writes disable CSRF, as petclinic-rest does.
 */

/++
`org.springframework.security.web.csrf`: cross-site request forgery protection.
+/
module flint.security.web.csrf;

import flint.jakarta.servlet : FilterChain;
import flint.jakarta.servlet.http : HttpServletRequest, HttpServletResponse;
import flint.security.access : AccessDeniedException;
import flint.security.web : SecurityFilter;
import flint.security.web.access : AccessDeniedHandler, AccessDeniedHandlerImpl;

@safe:

/// Thrown when a request lacks its CSRF token (Spring Security's `MissingCsrfTokenException`).
class MissingCsrfTokenException : AccessDeniedException
{
    /// `Could not verify the provided CSRF token because no token was found to compare.`
    this(string file = __FILE__, size_t line = __LINE__) pure nothrow
    {
        super("Could not verify the provided CSRF token because no token was found to compare.", null, file, line);
    }
}

/// Spring Security's `CsrfFilter`, without token repositories: safe methods pass, others are denied.
class CsrfFilter : SecurityFilter
{
    private AccessDeniedHandler accessDeniedHandler;

    /// A filter denying with `AccessDeniedHandlerImpl`.
    this()
    {
        accessDeniedHandler = new AccessDeniedHandlerImpl;
    }

    /// Set the handler.
    void setAccessDeniedHandler(AccessDeniedHandler handler) pure nothrow @nogc
    {
        accessDeniedHandler = handler;
    }

    override void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
    {
        const method = request.getMethod();
        if (method == "GET" || method == "HEAD" || method == "TRACE" || method == "OPTIONS")
        {
            chain.doFilter(request, response);
            return;
        }
        accessDeniedHandler.handle(request, response, new MissingCsrfTokenException);
    }
}
