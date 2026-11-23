// Ported from spring-security 7.2.0: web/src/main/java/org/springframework/security/web/authentication
// Copyright 2004-present the original author or authors.
// Licensed under the Apache License, Version 2.0.
// Modified by the Flint authors.
/*
 * Ported from spring-security 7.2.0, web/src/main/java/org/springframework/security/web/authentication/{
 * AnonymousAuthenticationFilter,Http403ForbiddenEntryPoint}.java.
 */

/++
`org.springframework.security.web.authentication`: anonymous authentication and the default entry point.
+/
module flint.security.web.authentication;

import flint.engine.aot.any : Any;
import flint.jakarta.servlet : FilterChain;
import flint.jakarta.servlet.http : HttpServletRequest, HttpServletResponse;
import flint.security.authentication : AnonymousAuthenticationToken;
import flint.security.core : AuthenticationException, AuthorityUtils, GrantedAuthority;
import flint.security.core.context : SecurityContextHolder;
import flint.security.web : AuthenticationEntryPoint, SecurityFilter;

@safe:

/// Sets an anonymous authentication when there is none (Spring Security's `AnonymousAuthenticationFilter`).
class AnonymousAuthenticationFilter : SecurityFilter
{
    private string key;
    private Any principal;
    private GrantedAuthority[] authorities;

    /// A filter with principal `anonymousUser` and authority `ROLE_ANONYMOUS`.
    this(string key)
    {
        this(key, Any.of("anonymousUser"), AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));
    }

    /// A filter with `principal` and `authorities`.
    this(string key, Any principal, GrantedAuthority[] authorities)
    {
        this.key = key;
        this.principal = principal;
        this.authorities = authorities;
    }

    override void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
    {
        auto context = SecurityContextHolder.getContext();
        if (context.getAuthentication() is null)
            context.setAuthentication(new AnonymousAuthenticationToken(key, principal, authorities));
        chain.doFilter(request, response);
    }
}

/// Answers `403 Forbidden` (Spring Security's `Http403ForbiddenEntryPoint`, the default without a login method).
class Http403ForbiddenEntryPoint : AuthenticationEntryPoint
{
    /// `sendError(403, "Access Denied")`.
    void commence(HttpServletRequest, HttpServletResponse response, AuthenticationException)
    {
        response.sendError(HttpServletResponse.SC_FORBIDDEN, "Access Denied");
    }
}
