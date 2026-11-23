// Ported from spring-security 7.2.0: core/src/main/java/org/springframework/security/access/expression/SecurityExpressionRoot.java
// Copyright 2004-present the original author or authors.
// Licensed under the Apache License, Version 2.0.
// Modified by the Flint authors.
/*
 * The expression root is an EvaluationContext of Flint AOT's compiled SpEL (contract 3): its root functions and
 * properties are SecurityExpressionRoot's, and arguments, beans and placeholders come from the invocation and the
 * context. Permission evaluators (hasPermission) are not ported.
 */

/++
`org.springframework.security.access.expression`: the root of security expressions.
+/
module flint.security.access.expression;

import flint.engine.aot.any : Any;
import flint.engine.aot.expression : EvaluationContext;
import flint.java.lang : IllegalArgumentException;
import flint.security.authentication : AuthenticationTrustResolverImpl;
import flint.security.core : Authentication;

@safe:

/++
Spring Security's `SecurityExpressionRoot`: `hasRole`, `hasAnyRole`, `hasAuthority`, `hasAnyAuthority`,
`isAuthenticated`, `isFullyAuthenticated`, `isAnonymous`, `isRememberMe`, `permitAll`, `denyAll`, and the
`authentication` and `principal` properties. `hasRole` prefixes `ROLE_` unless the role already has it.
+/
abstract class SecurityExpressionRoot : EvaluationContext
{
    private Authentication delegate() @safe authenticationSupplier;
    private Authentication authentication;
    private bool resolved;
    private string defaultRolePrefix = "ROLE_";

    /// A root over the authentication `supplier` gives on first use.
    this(Authentication delegate() @safe supplier)
    {
        authenticationSupplier = supplier;
    }

    /// The authentication, or null.
    final Authentication getAuthentication()
    {
        if (!resolved)
        {
            authentication = authenticationSupplier();
            resolved = true;
        }
        return authentication;
    }

    /// The prefix `hasRole` adds (`ROLE_`); null for none.
    final void setDefaultRolePrefix(string prefix) pure nothrow @nogc
    {
        defaultRolePrefix = prefix is null ? "" : prefix;
    }

    /// Whether the authentication holds `authority`.
    final bool hasAuthority(string authority)
    {
        return hasAnyAuthority(authority);
    }

    /// Whether it holds any of `authorities`.
    final bool hasAnyAuthority(string[] authorities...)
    {
        return hasAnyAuthorityName(null, authorities);
    }

    /// Whether it holds the role (`ROLE_` added unless present).
    final bool hasRole(string role)
    {
        return hasAnyRole(role);
    }

    /// Whether it holds any of the roles.
    final bool hasAnyRole(string[] roles...)
    {
        return hasAnyAuthorityName(defaultRolePrefix, roles);
    }

    /// Whether authenticated and not anonymous.
    final bool isAuthenticated()
    {
        return new AuthenticationTrustResolverImpl().isAuthenticated(getAuthentication());
    }

    /// Whether fully authenticated.
    final bool isFullyAuthenticated()
    {
        return new AuthenticationTrustResolverImpl().isFullyAuthenticated(getAuthentication());
    }

    /// Whether anonymous.
    final bool isAnonymous()
    {
        return new AuthenticationTrustResolverImpl().isAnonymous(getAuthentication());
    }

    private bool hasAnyAuthorityName(string prefix, scope string[] names)
    {
        auto current = getAuthentication();
        if (current is null || !current.isAuthenticated())
            return false;
        foreach (held; current.getAuthorities())
            foreach (name; names)
            {
                const wanted = prefix.length && !(name.length >= prefix.length
                        && name[0 .. prefix.length] == prefix) ? prefix ~ name : name;
                if (held.getAuthority() == wanted)
                    return true;
            }
        return false;
    }

    /// The root functions, by name: their arguments are strings.
    Any rootFunction(string name, scope Any[] arguments)
    {
        string[] texts;
        foreach (argument; arguments)
            texts ~= argument.typeName == "string" ? argument.get!string : argument.toString();
        return Any.of(evaluateFunction(name, texts));
    }

    private bool evaluateFunction(string name, string[] texts)
    {
        switch (name)
        {
        case "hasRole", "hasAnyRole":
            return hasAnyRole(texts);
        case "hasAuthority", "hasAnyAuthority":
            return hasAnyAuthority(texts);
        case "isAuthenticated":
            return isAuthenticated();
        case "isFullyAuthenticated":
            return isFullyAuthenticated();
        case "isAnonymous":
            return isAnonymous();
        case "permitAll":
            return true;
        case "isRememberMe", "denyAll", "hasPermission": // no remember-me; Spring's default DenyAllPermissionEvaluator
            return false;
        default:
            throw new IllegalArgumentException("Unknown security expression function '" ~ name ~ "'");
        }
    }

    private static Any principalUsername(Authentication current)
    {
        import flint.security.core.userdetails : UserDetails;

        if (current is null)
            return Any.init;
        auto details = cast(UserDetails) current.getPrincipal().asObject();
        return Any.of(details !is null ? details.getUsername() : current.getName());
    }

    /++
    `authentication`, `principal`, `permitAll`, `denyAll`, and the dotted paths `authentication.name`,
    `authentication.principal`, `authentication.authenticated` and `principal.username`.
    +/
    Any rootProperty(string name)
    {
        auto current = getAuthentication();
        switch (name)
        {
        case "authentication":
            return Any.of(cast(Object) current);
        case "principal", "authentication.principal":
            return current is null ? Any.init : current.getPrincipal();
        case "authentication.name":
            return current is null ? Any.init : Any.of(current.getName());
        case "authentication.authenticated":
            return Any.of(current !is null && current.isAuthenticated());
        case "principal.username":
            return principalUsername(current);
        case "permitAll":
            return Any.of(true);
        case "denyAll":
            return Any.of(false);
        default:
            throw new IllegalArgumentException("Unknown security expression property '" ~ name ~ "'");
        }
    }
}
