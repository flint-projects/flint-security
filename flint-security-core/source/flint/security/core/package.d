// Ported from spring-security 7.2.0: core/src/main/java/org/springframework/security/core
// Copyright 2004-present the original author or authors.
// Licensed under the Apache License, Version 2.0.
// Modified by the Flint authors.
/*
 * Ported from spring-security 7.2.0, core/src/main/java/org/springframework/security/core/{Authentication,
 * GrantedAuthority,AuthenticationException,CredentialsContainer,SpringSecurityMessageSource}.java and
 * core/authority/{SimpleGrantedAuthority,AuthorityUtils}.java. Principals, credentials and details are Any (Java's
 * Object); a principal that is an object is held as one.
 */

/++
`org.springframework.security.core`: authentication tokens and granted authorities.
+/
module flint.security.core;

import flint.engine.aot.any : Any;
import flint.java.lang : IllegalArgumentException, RuntimeException;

@safe:

/// An authority granted to a principal, such as `ROLE_ADMIN` (Spring Security's `GrantedAuthority`).
interface GrantedAuthority
{
    /// The authority's text; null when it cannot be expressed as a string.
    string getAuthority();
}

/// A token for an authentication request, or for an authenticated principal (Spring Security's `Authentication`).
interface Authentication
{
    /// The authorities granted to the principal.
    GrantedAuthority[] getAuthorities();
    /// The credentials that prove the principal, usually a password.
    Any getCredentials();
    /// Additional details: an IP address, a session id.
    Any getDetails();
    /// The principal: a `UserDetails` once authenticated, the user name before.
    Any getPrincipal();
    /// Whether the token is authenticated.
    bool isAuthenticated();
    /// Mark the token (un)authenticated. Throws `IllegalArgumentException` when a token cannot be trusted.
    void setAuthenticated(bool isAuthenticated);
    /// The principal's name (Java's `Principal.getName`).
    string getName();
}

/// Something holding credentials that can be erased after authentication.
interface CredentialsContainer
{
    /// Forget the credentials.
    void eraseCredentials();
}

/// The base of authentication failures (Spring Security's `AuthenticationException`).
abstract class AuthenticationException : RuntimeException
{
    private Authentication authenticationRequest;

    /// A failure with `message`.
    this(string message, Throwable cause = null, string file = __FILE__, size_t line = __LINE__) pure nothrow
    {
        super(message, cause, file, line);
    }

    /// The request that failed, or null.
    Authentication getAuthenticationRequest() pure nothrow @nogc
    {
        return authenticationRequest;
    }

    /// Record the request that failed.
    void setAuthenticationRequest(Authentication authenticationRequest) pure nothrow @nogc
    {
        this.authenticationRequest = authenticationRequest;
    }
}

/// A `GrantedAuthority` holding its text (Spring Security's `SimpleGrantedAuthority`).
final class SimpleGrantedAuthority : GrantedAuthority
{
    private string role;

    /// The authority `role`. Throws `IllegalArgumentException` for an empty one.
    this(string role)
    {
        if (role.length == 0)
            throw new IllegalArgumentException("A granted authority textual representation is required");
        this.role = role;
    }

    /// The authority text.
    string getAuthority()
    {
        return role;
    }

    /// Equal authority text.
    override bool opEquals(Object obj)
    {
        auto that = cast(SimpleGrantedAuthority) obj;
        return that !is null && that.role == role;
    }

    /// The text's hash.
    override size_t toHash() nothrow
    {
        return hashOf(role);
    }

    /// The authority text.
    override string toString()
    {
        return role;
    }
}

/// Helpers for authority collections (Spring Security's `AuthorityUtils`).
struct AuthorityUtils
{
    /// No authorities.
    enum GrantedAuthority[] NO_AUTHORITIES = null;

    /// The authorities named, as `SimpleGrantedAuthority`s.
    static GrantedAuthority[] createAuthorityList(string[] authorities...)
    {
        GrantedAuthority[] result;
        foreach (authority; authorities)
            result ~= new SimpleGrantedAuthority(authority);
        return result;
    }

    /// The authorities of a comma-separated list.
    static GrantedAuthority[] commaSeparatedStringToAuthorityList(string authorityString)
    {
        GrantedAuthority[] result;
        size_t start;
        foreach (i; 0 .. authorityString.length + 1)
            if (i == authorityString.length || authorityString[i] == ',')
            {
                auto text = trim(authorityString[start .. i]);
                if (text.length)
                    result ~= new SimpleGrantedAuthority(text);
                start = i + 1;
            }
        return result;
    }

    /// The text of each authority.
    static string[] authorityListToSet(GrantedAuthority[] authorities)
    {
        string[] result;
        foreach (authority; authorities)
        {
            bool present;
            foreach (existing; result)
                present |= existing == authority.getAuthority();
            if (!present)
                result ~= authority.getAuthority();
        }
        return result;
    }

    private static string trim(string text) pure nothrow @nogc
    {
        size_t start, end = text.length;
        while (start < end && text[start] == ' ')
            start++;
        while (end > start && text[end - 1] == ' ')
            end--;
        return text[start .. end];
    }
}

/// `[a, b]`, as Java prints a collection of authorities.
package(flint.security) string authoritiesText(GrantedAuthority[] authorities)
{
    import flint.java.lang : valueOf;

    string result = "[";
    foreach (i, authority; authorities)
        result ~= (i ? ", " : "") ~ valueOf(cast(Object) authority);
    return result ~ "]";
}
