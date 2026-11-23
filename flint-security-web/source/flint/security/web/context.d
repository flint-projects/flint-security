// Ported from spring-security 7.2.0: web/src/main/java/org/springframework/security/web/context
// Copyright 2004-present the original author or authors.
// Licensed under the Apache License, Version 2.0.
// Modified by the Flint authors.
/*
 * Ported from spring-security 7.2.0, web/src/main/java/org/springframework/security/web/context/{
 * SecurityContextRepository,RequestAttributeSecurityContextRepository,SecurityContextHolderFilter}.java. The HTTP
 * session repository is not ported (the servlet port has no sessions yet), so a context lives for one request and
 * its dispatches.
 */

/++
`org.springframework.security.web.context`: loading and saving the security context per request.
+/
module flint.security.web.context;

import flint.engine.aot.any : Any;
import flint.jakarta.servlet : FilterChain;
import flint.jakarta.servlet.http : HttpServletRequest, HttpServletResponse;
import flint.security.core.context : SecurityContext, SecurityContextHolder;
import flint.security.web : SecurityFilter;

@safe:

/// Persists the security context between dispatches (Spring Security's `SecurityContextRepository`).
interface SecurityContextRepository
{
    /// The context saved for `request`, or null.
    SecurityContext loadContext(HttpServletRequest request);
    /// Save `context` for `request`.
    void saveContext(SecurityContext context, HttpServletRequest request, HttpServletResponse response);
    /// Whether `request` has a saved context.
    bool containsContext(HttpServletRequest request);
}

/// Keeps the context in a request attribute, so the error dispatch of the same request sees it.
class RequestAttributeSecurityContextRepository : SecurityContextRepository
{
    /// The attribute name.
    enum DEFAULT_REQUEST_ATTR_NAME = "flint.security.web.context.RequestAttributeSecurityContextRepository"
        ~ ".SPRING_SECURITY_CONTEXT";

    /// The saved context, or null.
    SecurityContext loadContext(HttpServletRequest request)
    {
        return cast(SecurityContext) request.getAttribute(DEFAULT_REQUEST_ATTR_NAME).asObject();
    }

    /// Save it as an attribute.
    void saveContext(SecurityContext context, HttpServletRequest request, HttpServletResponse)
    {
        request.setAttribute(DEFAULT_REQUEST_ATTR_NAME, Any.of(cast(Object) context));
    }

    /// Whether the attribute is set.
    bool containsContext(HttpServletRequest request)
    {
        return loadContext(request) !is null;
    }
}

/// Loads the saved context into the holder for the rest of the chain, and clears it after (Spring Security's
/// `SecurityContextHolderFilter`).
class SecurityContextHolderFilter : SecurityFilter
{
    private SecurityContextRepository repository;

    /// A filter over `repository`.
    this(SecurityContextRepository repository)
    {
        this.repository = repository;
    }

    override void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
    {
        auto context = repository.loadContext(request);
        if (context !is null)
            SecurityContextHolder.setContext(context);
        scope (exit)
            SecurityContextHolder.clearContext();
        chain.doFilter(request, response);
    }
}
