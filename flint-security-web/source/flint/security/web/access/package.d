// Ported from spring-security 7.2.0: web/src/main/java/org/springframework/security/web/access
// Copyright 2004-present the original author or authors.
// Licensed under the Apache License, Version 2.0.
// Modified by the Flint authors.
/*
 * Ported from spring-security 7.2.0, web/src/main/java/org/springframework/security/web/access/{
 * ExceptionTranslationFilter,AccessDeniedHandler,AccessDeniedHandlerImpl}.java and access/intercept/{
 * AuthorizationFilter,RequestAuthorizationContext,RequestMatcherDelegatingAuthorizationManager}.java. The request
 * cache is not ported. A failure wrapped by another exception is found by walking the cause chain, as Spring's
 * ThrowableAnalyzer does.
 */

/++
`org.springframework.security.web.access`: turning security failures into responses, and authorizing requests.
+/
module flint.security.web.access;

import flint.jakarta.servlet : FilterChain;
import flint.jakarta.servlet.http : HttpServletRequest, HttpServletResponse;
import flint.java.lang : IllegalArgumentException;
import flint.security.access : AccessDeniedException;
import flint.security.authentication : AuthenticationTrustResolverImpl, InsufficientAuthenticationException;
import flint.security.authorization : AuthenticationSupplier, AuthorizationDecision,
    AuthorizationDeniedException, AuthorizationManager, AuthorizationResult;
import flint.security.core : Authentication, AuthenticationException;
import flint.security.core.context : SecurityContextHolder;
import flint.security.web : AuthenticationEntryPoint, SecurityFilter;
import flint.security.web.util.matcher : RequestMatcher;

@safe:

/// Handles an access-denied failure (Spring Security's `AccessDeniedHandler`).
interface AccessDeniedHandler
{
    /// Answer the denial.
    void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException exception);
}

/// `sendError(403, "Forbidden")` (Spring Security's `AccessDeniedHandlerImpl`).
class AccessDeniedHandlerImpl : AccessDeniedHandler
{
    /// Send 403 unless committed.
    void handle(HttpServletRequest, HttpServletResponse response, AccessDeniedException)
    {
        if (!response.isCommitted())
            response.sendError(HttpServletResponse.SC_FORBIDDEN, "Forbidden");
    }
}

/++
Spring Security's `ExceptionTranslationFilter`: an `AuthenticationException` starts authentication at the entry
point; an `AccessDeniedException` does too for an anonymous user, and otherwise goes to the access-denied handler.
+/
class ExceptionTranslationFilter : SecurityFilter
{
    private AuthenticationEntryPoint authenticationEntryPoint;
    private AccessDeniedHandler accessDeniedHandler;

    /// A filter starting authentication at `authenticationEntryPoint`.
    this(AuthenticationEntryPoint authenticationEntryPoint)
    {
        if (authenticationEntryPoint is null)
            throw new IllegalArgumentException("authenticationEntryPoint cannot be null");
        this.authenticationEntryPoint = authenticationEntryPoint;
        accessDeniedHandler = new AccessDeniedHandlerImpl;
    }

    /// Set the access-denied handler.
    void setAccessDeniedHandler(AccessDeniedHandler handler)
    {
        if (handler is null)
            throw new IllegalArgumentException("AccessDeniedHandler required");
        accessDeniedHandler = handler;
    }

    override void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
    {
        try
            chain.doFilter(request, response);
        catch (Exception e)
        {
            for (Throwable cause = e; cause !is null; cause = cause.next)
            {
                if (auto authentication = cast(AuthenticationException) cause)
                    return sendStartAuthentication(request, response, authentication);
                if (auto denied = cast(AccessDeniedException) cause)
                    return handleAccessDenied(request, response, denied);
            }
            throw e;
        }
    }

    private void handleAccessDenied(HttpServletRequest request, HttpServletResponse response,
            AccessDeniedException exception)
    {
        auto current = SecurityContextHolder.getContext().getAuthentication();
        auto resolver = new AuthenticationTrustResolverImpl;
        if (resolver.isAnonymous(current) || resolver.isRememberMe(current))
        {
            auto insufficient = new InsufficientAuthenticationException(
                    "Full authentication is required to access this resource", exception);
            insufficient.setAuthenticationRequest(current);
            sendStartAuthentication(request, response, insufficient);
        }
        else
            accessDeniedHandler.handle(request, response, exception);
    }

    /// Clear the context and commence authentication.
    protected void sendStartAuthentication(HttpServletRequest request, HttpServletResponse response,
            AuthenticationException reason)
    {
        SecurityContextHolder.setContext(SecurityContextHolder.createEmptyContext());
        authenticationEntryPoint.commence(request, response, reason);
    }
}

/// The request being authorized (Spring Security's `RequestAuthorizationContext`).
final class RequestAuthorizationContext
{
    private HttpServletRequest request;

    /// A context for `request`.
    this(HttpServletRequest request)
    {
        this.request = request;
    }

    /// The request.
    HttpServletRequest getRequest()
    {
        return request;
    }
}

/// The request rules, first match wins (Spring Security's `RequestMatcherDelegatingAuthorizationManager`).
class RequestMatcherDelegatingAuthorizationManager : AuthorizationManager!HttpServletRequest
{
    private RequestMatcher[] matchers;
    private AuthorizationManager!RequestAuthorizationContext[] managers;

    /// Add a rule.
    void add(RequestMatcher matcher, AuthorizationManager!RequestAuthorizationContext manager)
    {
        matchers ~= matcher;
        managers ~= manager;
    }

    /// The first matching rule's decision; denied when none matches.
    AuthorizationResult authorize(AuthenticationSupplier authentication, HttpServletRequest request)
    {
        foreach (i, matcher; matchers)
            if (matcher.matches(request))
                return managers[i].authorize(authentication, new RequestAuthorizationContext(request));
        return new AuthorizationDecision(false);
    }
}

/// Spring Security's `AuthorizationFilter`: authorizes each dispatch, throwing `AuthorizationDeniedException`.
class AuthorizationFilter : SecurityFilter
{
    private AuthorizationManager!HttpServletRequest authorizationManager;

    /// A filter over `authorizationManager`.
    this(AuthorizationManager!HttpServletRequest authorizationManager)
    {
        if (authorizationManager is null)
            throw new IllegalArgumentException("authorizationManager cannot be null");
        this.authorizationManager = authorizationManager;
    }

    override void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
    {
        auto result = authorizationManager.authorize(&currentAuthentication, request);
        if (result !is null && !result.isGranted())
            throw new AuthorizationDeniedException("Access Denied", result);
        chain.doFilter(request, response);
    }

    private Authentication currentAuthentication()
    {
        import flint.security.authentication : AuthenticationCredentialsNotFoundException;

        auto current = SecurityContextHolder.getContext().getAuthentication();
        if (current is null)
            throw new AuthenticationCredentialsNotFoundException(
                    "An Authentication object was not found in the SecurityContext");
        return current;
    }
}
