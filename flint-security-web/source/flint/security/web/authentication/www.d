// Ported from spring-security 7.2.0: web/src/main/java/org/springframework/security/web/authentication/www
// Copyright 2004-present the original author or authors.
// Licensed under the Apache License, Version 2.0.
// Modified by the Flint authors.
/*
 * Ported from spring-security 7.2.0, web/src/main/java/org/springframework/security/web/authentication/www/{
 * BasicAuthenticationFilter,BasicAuthenticationEntryPoint,BasicAuthenticationConverter}.java. Remember-me services
 * are not ported; credentials are decoded as UTF-8 (Spring's default charset).
 */

/++
`org.springframework.security.web.authentication.www`: HTTP Basic authentication.
+/
module flint.security.web.authentication.www;

import flint.engine.aot.any : Any;
import flint.jakarta.servlet : FilterChain;
import flint.jakarta.servlet.http : HttpServletRequest, HttpServletResponse;
import flint.java.lang : IllegalArgumentException;
import flint.security.authentication : AuthenticationManager, BadCredentialsException,
    UsernamePasswordAuthenticationToken;
import flint.security.core : AuthenticationException;
import flint.security.core.context : SecurityContextHolder, SecurityContextImpl;
import flint.security.web : AuthenticationEntryPoint, SecurityFilter;
import flint.security.web.context : SecurityContextRepository;

@safe:

/// Answers `401` with `WWW-Authenticate: Basic realm="..."` (Spring Security's `BasicAuthenticationEntryPoint`).
class BasicAuthenticationEntryPoint : AuthenticationEntryPoint
{
    private string realmName;

    /// Set the realm.
    void setRealmName(string realmName) pure nothrow @nogc
    {
        this.realmName = realmName;
    }

    /// The realm.
    string getRealmName() const pure nothrow @nogc
    {
        return realmName;
    }

    /// `WWW-Authenticate: Basic realm="<realm>"` and `sendError(401, "Unauthorized")`.
    void commence(HttpServletRequest, HttpServletResponse response, AuthenticationException)
    {
        response.setHeader("WWW-Authenticate", "Basic realm=\"" ~ realmName ~ "\"");
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized");
    }
}

/// Reads `Authorization: Basic <base64(user:password)>` (Spring Security's `BasicAuthenticationConverter`).
struct BasicAuthenticationConverter
{
    /// The unauthenticated token, or null without a Basic header. Throws `BadCredentialsException` for a malformed
    /// one.
    static UsernamePasswordAuthenticationToken convert(HttpServletRequest request)
    {
        import std.base64 : Base64;

        auto header = request.getHeader("Authorization");
        if (header is null)
            return null;
        header = trim(header);
        if (header.length < 5 || !equalsIgnoreCase(header[0 .. 5], "basic"))
            return null;
        if (header.length == 5)
            throw new BadCredentialsException("Empty basic authentication token");
        const encoded = trim(header[6 .. $]);
        string token;
        try
            token = cast(string) Base64.decode(encoded).idup;
        catch (Exception)
            throw new BadCredentialsException("Failed to decode basic authentication token");
        foreach (i, c; token)
            if (c == ':')
                return UsernamePasswordAuthenticationToken.unauthenticated(Any.of(token[0 .. i]),
                        Any.of(token[i + 1 .. $]));
        throw new BadCredentialsException("Invalid basic authentication token");
    }

    private static string trim(string text) pure nothrow @nogc
    {
        size_t start, end = text.length;
        while (start < end && (text[start] == ' ' || text[start] == '\t'))
            start++;
        while (end > start && (text[end - 1] == ' ' || text[end - 1] == '\t'))
            end--;
        return text[start .. end];
    }

    private static bool equalsIgnoreCase(string a, string b) pure nothrow @nogc
    {
        if (a.length != b.length)
            return false;
        foreach (i, c; a)
            if ((c | 0x20) != (b[i] | 0x20))
                return false;
        return true;
    }
}

/++
Spring Security's `BasicAuthenticationFilter`: authenticates the Basic credentials of a request through the
authentication manager; a failure clears the context and starts authentication at the entry point.
+/
class BasicAuthenticationFilter : SecurityFilter
{
    private AuthenticationManager authenticationManager;
    private AuthenticationEntryPoint authenticationEntryPoint;
    private SecurityContextRepository securityContextRepository;

    /// A filter authenticating with `authenticationManager` and failing at `authenticationEntryPoint`.
    this(AuthenticationManager authenticationManager, AuthenticationEntryPoint authenticationEntryPoint)
    {
        if (authenticationManager is null)
            throw new IllegalArgumentException("An AuthenticationManager is required");
        if (authenticationEntryPoint is null)
            throw new IllegalArgumentException("An AuthenticationEntryPoint is required");
        this.authenticationManager = authenticationManager;
        this.authenticationEntryPoint = authenticationEntryPoint;
    }

    /// Where the authenticated context is saved.
    void setSecurityContextRepository(SecurityContextRepository repository) pure nothrow @nogc
    {
        securityContextRepository = repository;
    }

    override void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
    {
        try
        {
            auto token = BasicAuthenticationConverter.convert(request);
            if (token !is null && authenticationIsRequired(token.getName()))
            {
                auto result = authenticationManager.authenticate(token);
                auto context = new SecurityContextImpl(result);
                SecurityContextHolder.setContext(context);
                if (securityContextRepository !is null)
                    securityContextRepository.saveContext(context, request, response);
            }
        }
        catch (AuthenticationException e)
        {
            SecurityContextHolder.clearContext();
            authenticationEntryPoint.commence(request, response, e);
            return;
        }
        chain.doFilter(request, response);
    }

    /// Whether the current authentication is absent, unauthenticated, anonymous or for another user.
    private static bool authenticationIsRequired(string username)
    {
        import flint.security.authentication : AnonymousAuthenticationToken;

        auto existing = SecurityContextHolder.getContext().getAuthentication();
        if (existing is null || !existing.isAuthenticated())
            return true;
        if (cast(AnonymousAuthenticationToken) existing !is null)
            return true;
        return existing.getName() != username;
    }
}
