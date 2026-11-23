// Ported from spring-security 7.2.0: core/src/main/java/org/springframework/security/authorization
// Copyright 2004-present the original author or authors.
// Licensed under the Apache License, Version 2.0.
// Modified by the Flint authors.
/*
 * Ported from spring-security 7.2.0, core/src/main/java/org/springframework/security/authorization/{
 * AuthorizationResult,AuthorizationDecision,AuthorizationManager,AuthorizationDeniedException,
 * AuthorityAuthorizationManager,AuthenticatedAuthorizationManager,AuthorityAuthorizationDecision}.java.
 * AuthorizationManager<T> is the template AuthorizationManager!T; the authentication supplier is a delegate.
 */

/++
`org.springframework.security.authorization`: access decisions.
+/
module flint.security.authorization;

import flint.java.lang : IllegalArgumentException, valueOf;
import flint.security.access : AccessDeniedException;
import flint.security.authentication : AuthenticationTrustResolverImpl;
import flint.security.core : Authentication, authoritiesText, AuthorityUtils, GrantedAuthority;

@safe:

/// The outcome of an authorization check.
interface AuthorizationResult
{
    /// Whether access is granted.
    bool isGranted();
}

/// Spring Security's `AuthorizationDecision`.
class AuthorizationDecision : AuthorizationResult
{
    private bool granted;

    /// A decision.
    this(bool granted) pure nothrow @nogc
    {
        this.granted = granted;
    }

    /// Whether granted.
    bool isGranted()
    {
        return granted;
    }

    /// `AuthorizationDecision [granted=...]`.
    override string toString()
    {
        return "AuthorizationDecision [granted=" ~ valueOf(granted) ~ "]";
    }
}

/// A decision on authorities (Spring Security's `AuthorityAuthorizationDecision`).
class AuthorityAuthorizationDecision : AuthorizationDecision
{
    private GrantedAuthority[] authorities;

    /// A decision naming the required `authorities`.
    this(bool granted, GrantedAuthority[] authorities)
    {
        super(granted);
        this.authorities = authorities;
    }

    /// The authorities required.
    GrantedAuthority[] getAuthorities()
    {
        return authorities.dup;
    }

    /// `AuthorityAuthorizationDecision [granted=..., authorities=[...]]`.
    override string toString()
    {
        return "AuthorityAuthorizationDecision [granted=" ~ valueOf(
                isGranted()) ~ ", authorities=" ~ authoritiesText(authorities) ~ "]";
    }
}

/// Supplies the current authentication when a decision needs it.
alias AuthenticationSupplier = Authentication delegate() @safe;

/// Decides whether an authentication may access an object of type `T` (Spring Security's `AuthorizationManager`).
interface AuthorizationManager(T)
{
    /// The decision, or null to abstain.
    AuthorizationResult authorize(AuthenticationSupplier authentication, T object);

    /// Throw `AuthorizationDeniedException` unless granted.
    final void verify(AuthenticationSupplier authentication, T object)
    {
        auto result = authorize(authentication, object);
        if (result !is null && !result.isGranted())
            throw new AuthorizationDeniedException("Access Denied", result);
    }
}

/// Thrown when an authorization manager denies access (Spring Security's `AuthorizationDeniedException`).
class AuthorizationDeniedException : AccessDeniedException
{
    private AuthorizationResult result;

    /// A denial with `message` and its `result`.
    this(string message, AuthorizationResult result = null, string file = __FILE__, size_t line = __LINE__)
    {
        super(message, null, file, line);
        this.result = result is null ? new AuthorizationDecision(false) : result;
    }

    /// The denying result.
    AuthorizationResult getAuthorizationResult() pure nothrow @nogc
    {
        return result;
    }
}

/// Grants when the authentication holds any of the authorities (Spring Security's `AuthorityAuthorizationManager`).
final class AuthorityAuthorizationManager(T) : AuthorizationManager!T
{
    private GrantedAuthority[] authorities;

    private this(GrantedAuthority[] authorities)
    {
        this.authorities = authorities;
    }

    /// Requires `ROLE_<role>`. Throws `IllegalArgumentException` for a role that already has the prefix.
    static AuthorityAuthorizationManager!T hasRole(string role)
    {
        return hasAnyRole(role);
    }

    /// Requires any of `ROLE_<role>`.
    static AuthorityAuthorizationManager!T hasAnyRole(string[] roles...)
    {
        string[] named;
        foreach (role; roles)
        {
            if (role.length >= 5 && role[0 .. 5] == "ROLE_")
                throw new IllegalArgumentException(role ~ " should not start with ROLE_ since ROLE_ is "
                        ~ "automatically prepended when using hasAnyRole. Consider using hasAnyAuthority instead.");
            named ~= "ROLE_" ~ role;
        }
        return new AuthorityAuthorizationManager!T(AuthorityUtils.createAuthorityList(named));
    }

    /// Requires `authority`.
    static AuthorityAuthorizationManager!T hasAuthority(string authority)
    {
        return hasAnyAuthority(authority);
    }

    /// Requires any of `authorities`.
    static AuthorityAuthorizationManager!T hasAnyAuthority(string[] authorities...)
    {
        return new AuthorityAuthorizationManager!T(AuthorityUtils.createAuthorityList(authorities));
    }

    /// Granted when the authentication is authenticated and holds a required authority.
    AuthorizationResult authorize(AuthenticationSupplier authentication, T)
    {
        return new AuthorityAuthorizationDecision(isGranted(authentication(), authorities), authorities);
    }

    /// Whether `authentication` is authenticated and holds any of `required`.
    static bool isGranted(Authentication authentication, GrantedAuthority[] required)
    {
        if (authentication is null || !authentication.isAuthenticated())
            return false;
        foreach (held; authentication.getAuthorities())
            foreach (want; required)
                if (held.getAuthority() == want.getAuthority())
                    return true;
        return false;
    }
}

/// Grants authenticated, non-anonymous principals (Spring Security's `AuthenticatedAuthorizationManager`).
final class AuthenticatedAuthorizationManager(T) : AuthorizationManager!T
{
    private bool anonymous;

    /// Requires an authenticated, non-anonymous principal.
    static AuthenticatedAuthorizationManager!T authenticated()
    {
        return new AuthenticatedAuthorizationManager!T;
    }

    /// Requires an anonymous principal.
    static AuthenticatedAuthorizationManager!T anonymous_()
    {
        auto manager = new AuthenticatedAuthorizationManager!T;
        manager.anonymous = true;
        return manager;
    }

    /// The decision.
    AuthorizationResult authorize(AuthenticationSupplier authentication, T)
    {
        auto resolver = new AuthenticationTrustResolverImpl;
        auto current = authentication();
        return new AuthorizationDecision(anonymous ? resolver.isAnonymous(current) : resolver.isAuthenticated(current));
    }
}

/// Always grants, or always denies.
final class SingleResultAuthorizationManager(T) : AuthorizationManager!T
{
    private bool granted;

    /// `permitAll`.
    static SingleResultAuthorizationManager!T permitAll()
    {
        return new SingleResultAuthorizationManager!T(true);
    }

    /// `denyAll`.
    static SingleResultAuthorizationManager!T denyAll()
    {
        return new SingleResultAuthorizationManager!T(false);
    }

    private this(bool granted) pure nothrow @nogc
    {
        this.granted = granted;
    }

    /// The fixed decision.
    AuthorizationResult authorize(AuthenticationSupplier, T)
    {
        return new AuthorizationDecision(granted);
    }
}
