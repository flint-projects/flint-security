// Ported from spring-security 7.2.0: web/src/main/java/org/springframework/security/web
// Copyright 2004-present the original author or authors.
// Licensed under the Apache License, Version 2.0.
// Modified by the Flint authors.
/*
 * Ported from spring-security 7.2.0, web/src/main/java/org/springframework/security/web/{SecurityFilterChain,
 * DefaultSecurityFilterChain,FilterChainProxy,AuthenticationEntryPoint}.java. FilterChainProxy's firewall
 * (StrictHttpFirewall) and request rejection are not ported; it clears the context after each request, as Spring.
 */

/++
`org.springframework.security.web`: the security filter chains and the proxy that runs them.
+/
module flint.security.web;

import flint.jakarta.servlet : Filter, FilterChain, FilterConfig, ServletRequest, ServletResponse;
import flint.jakarta.servlet.http : HttpServletRequest, HttpServletResponse;
import flint.java.lang : IllegalArgumentException;
import flint.security.core : AuthenticationException;
import flint.security.core.context : SecurityContextHolder;
import flint.security.web.util.matcher : RequestMatcher;

@safe:

/// Starts authentication when it is required (Spring Security's `AuthenticationEntryPoint`).
interface AuthenticationEntryPoint
{
    /// Ask the client to authenticate, for example with `401` and `WWW-Authenticate`.
    void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException);
}

/// The filters for requests it matches (Spring Security's `SecurityFilterChain`).
interface SecurityFilterChain
{
    /// Whether this chain handles `request`.
    bool matches(HttpServletRequest request);
    /// The filters, in order.
    Filter[] getFilters();
}

/// Spring Security's `DefaultSecurityFilterChain`.
class DefaultSecurityFilterChain : SecurityFilterChain
{
    private RequestMatcher requestMatcher;
    private Filter[] filters;

    /// A chain of `filters` for requests `requestMatcher` matches.
    this(RequestMatcher requestMatcher, Filter[] filters...)
    {
        this.requestMatcher = requestMatcher;
        this.filters = filters.dup;
    }

    /// The matcher.
    RequestMatcher getRequestMatcher()
    {
        return requestMatcher;
    }

    /// The filters.
    Filter[] getFilters()
    {
        return filters.dup;
    }

    /// Whether the matcher matches.
    bool matches(HttpServletRequest request)
    {
        return requestMatcher.matches(request);
    }
}

/++
The single servlet filter in front of the security chains (Spring Security's `FilterChainProxy`, registered as
`springSecurityFilterChain`): runs the first matching chain's filters, then the rest of the servlet chain, and clears
the security context afterwards.
+/
class FilterChainProxy : Filter
{
    mixin Filter.Defaults;

    private SecurityFilterChain[] filterChains;

    /// A proxy over `filterChains`, tried in order.
    this(SecurityFilterChain[] filterChains...)
    {
        foreach (chain; filterChains)
            if (chain is null)
                throw new IllegalArgumentException("filterChains cannot contain null elements");
        this.filterChains = filterChains.dup;
    }

    /// The chains.
    SecurityFilterChain[] getFilterChains()
    {
        return filterChains.dup;
    }

    /// The filters of the first chain matching `request`; empty when none does.
    Filter[] getFilters(HttpServletRequest request)
    {
        foreach (chain; filterChains)
            if (chain.matches(request))
                return chain.getFilters();
        return null;
    }

    /// Run the matching chain, then `chain`; the context is cleared afterwards.
    void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
    {
        auto httpRequest = cast(HttpServletRequest) request;
        auto filters = httpRequest is null ? null : getFilters(httpRequest);
        scope (exit)
            SecurityContextHolder.clearContext();
        if (filters.length == 0)
        {
            chain.doFilter(request, response);
            return;
        }
        new VirtualFilterChain(chain, filters).doFilter(request, response);
    }
}

/// Runs the security filters, then the original chain.
private final class VirtualFilterChain : FilterChain
{
    private FilterChain originalChain;
    private Filter[] filters;
    private size_t position;

    this(FilterChain originalChain, Filter[] filters)
    {
        this.originalChain = originalChain;
        this.filters = filters;
    }

    void doFilter(ServletRequest request, ServletResponse response)
    {
        if (position == filters.length)
        {
            originalChain.doFilter(request, response);
            return;
        }
        auto next = filters[position++];
        next.doFilter(request, response, this);
    }
}

/// A filter that only handles HTTP requests, once per dispatch (Spring's `OncePerRequestFilter`, without the
/// already-filtered attribute: the chain proxy runs each filter once per dispatch).
abstract class SecurityFilter : Filter
{
    mixin Filter.Defaults;

    /// Filter HTTP requests; others pass through.
    final void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
    {
        auto httpRequest = cast(HttpServletRequest) request;
        auto httpResponse = cast(HttpServletResponse) response;
        if (httpRequest is null || httpResponse is null)
        {
            chain.doFilter(request, response);
            return;
        }
        doFilterInternal(httpRequest, httpResponse, chain);
    }

    /// Filter one HTTP request.
    protected abstract void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain);
}
