// Ported from spring-security 7.2.0: core/src/main/java/org/springframework/security/authentication
// Copyright 2004-present the original author or authors.
// Licensed under the Apache License, Version 2.0.
// Modified by the Flint authors.
/*
 * Ported from spring-security 7.2.0, core/src/main/java/org/springframework/security/authentication/{
 * AuthenticationManager,AuthenticationProvider,ProviderManager,AbstractAuthenticationToken,
 * UsernamePasswordAuthenticationToken,AnonymousAuthenticationToken,AuthenticationTrustResolver,
 * AuthenticationTrustResolverImpl,BadCredentialsException,AccountStatusException,DisabledException,LockedException,
 * AccountExpiredException,CredentialsExpiredException,ProviderNotFoundException,InsufficientAuthenticationException,
 * AuthenticationCredentialsNotFoundException,InternalAuthenticationServiceException}.java. supports(Class) takes the
 * token's type name (R4). Authentication events are not published.
 */

/++
`org.springframework.security.authentication`: authentication managers, providers and tokens.
+/
module flint.security.authentication;

import flint.engine.aot.any : Any;
import flint.engine.aot.name : canonicalTypeName, simpleTypeName;
import flint.java.lang : IllegalArgumentException, valueOf;
import flint.security.core : Authentication, AuthenticationException, authoritiesText,
    CredentialsContainer, GrantedAuthority;

@safe:

/// Processes an authentication request (Spring Security's `AuthenticationManager`).
interface AuthenticationManager
{
    /// The authenticated token. Throws an `AuthenticationException` when authentication fails.
    Authentication authenticate(Authentication authentication);
}

/// Authenticates one kind of token (Spring Security's `AuthenticationProvider`).
interface AuthenticationProvider
{
    /// The authenticated token, null when this provider cannot decide, or an `AuthenticationException`.
    Authentication authenticate(Authentication authentication);
    /// Whether tokens of the type named `authenticationType` are supported.
    bool supports(string authenticationType);
}

/// The canonical type name of `authentication`'s class.
string authenticationType(Authentication authentication)
{
    return canonicalTypeName(typeid(cast(Object) authentication).name);
}

/// The base of tokens: authorities, details and the authenticated flag (Spring Security's
/// `AbstractAuthenticationToken`).
abstract class AbstractAuthenticationToken : Authentication, CredentialsContainer
{
    private GrantedAuthority[] authorities;
    private Any details;
    private bool authenticated;

    /// A token with `authorities`. Throws `IllegalArgumentException` for a null element.
    this(GrantedAuthority[] authorities)
    {
        foreach (authority; authorities)
            if (authority is null)
                throw new IllegalArgumentException("Authorities collection cannot contain any null elements");
        this.authorities = authorities.dup;
    }

    /// The authorities.
    GrantedAuthority[] getAuthorities()
    {
        return authorities.dup;
    }

    /// The principal's name: a `UserDetails`' user name, else the principal's text, else empty.
    string getName()
    {
        import flint.security.core.userdetails : UserDetails;

        auto principal = getPrincipal();
        if (auto details = cast(UserDetails) principal.asObject())
            return details.getUsername();
        return principal.isNull ? "" : principal.typeName == "string" ? principal.get!string
            : valueOf(principal.asObject());
    }

    /// Whether authenticated.
    bool isAuthenticated()
    {
        return authenticated;
    }

    /// Set the flag.
    void setAuthenticated(bool authenticated)
    {
        this.authenticated = authenticated;
    }

    /// The details.
    Any getDetails()
    {
        return details;
    }

    /// Set the details.
    void setDetails(Any details)
    {
        this.details = details;
    }

    /// Erase the credentials, principal and details that hold them.
    void eraseCredentials()
    {
        eraseSecret(getCredentials());
        eraseSecret(getPrincipal());
        eraseSecret(details);
    }

    private static void eraseSecret(Any secret)
    {
        if (auto container = cast(CredentialsContainer) secret.asObject())
            container.eraseCredentials();
    }

    /// Equal class, authorities, details, credentials, principal and flag.
    override bool opEquals(Object obj)
    {
        auto that = cast(AbstractAuthenticationToken) obj;
        if (that is null || typeid(that) !is typeid(this) || that.authenticated != authenticated)
            return false;
        if (authoritiesText(authorities) != authoritiesText(that.authorities))
            return false;
        return details == that.details && getCredentials() == that.getCredentials()
            && getPrincipal() == that.getPrincipal();
    }

    /// The hash of the authorities and principal.
    override size_t toHash()
    {
        import flint.java.lang : javaHashCode;

        size_t code = 31;
        foreach (authority; authorities)
            code ^= javaHashCode(authority);
        return code;
    }

    /// `ClassName [Principal=..., Credentials=[PROTECTED], Authenticated=..., Details=..., Granted Authorities=[...]]`.
    override string toString()
    {
        return simpleTypeName(canonicalTypeName(typeid(this).name)) ~ " [Principal=" ~ getPrincipal()
            .toString() ~ ", Credentials=[PROTECTED], Authenticated=" ~ valueOf(
                authenticated) ~ ", Details=" ~ details.toString() ~ ", Granted Authorities=" ~ authoritiesText(
                authorities) ~ "]";
    }
}

/// A user name and password token (Spring Security's `UsernamePasswordAuthenticationToken`).
class UsernamePasswordAuthenticationToken : AbstractAuthenticationToken
{
    private Any principal;
    private Any credentials;

    /// An unauthenticated request for `principal` with `credentials`.
    this(Any principal, Any credentials)
    {
        super(null);
        this.principal = principal;
        this.credentials = credentials;
        super.setAuthenticated(false);
    }

    /// An authenticated token.
    this(Any principal, Any credentials, GrantedAuthority[] authorities)
    {
        super(authorities);
        this.principal = principal;
        this.credentials = credentials;
        super.setAuthenticated(true);
    }

    /// `unauthenticated(principal, credentials)`.
    static UsernamePasswordAuthenticationToken unauthenticated(Any principal, Any credentials)
    {
        return new UsernamePasswordAuthenticationToken(principal, credentials);
    }

    /// `authenticated(principal, credentials, authorities)`.
    static UsernamePasswordAuthenticationToken authenticated(Any principal, Any credentials,
            GrantedAuthority[] authorities)
    {
        return new UsernamePasswordAuthenticationToken(principal, credentials, authorities);
    }

    /// The credentials.
    Any getCredentials()
    {
        return credentials;
    }

    /// The principal.
    Any getPrincipal()
    {
        return principal;
    }

    /// Only false: use the constructor with authorities. Throws `IllegalArgumentException` for true.
    override void setAuthenticated(bool isAuthenticated)
    {
        if (isAuthenticated)
            throw new IllegalArgumentException(
                    "Cannot set this token to trusted - use constructor which takes a "
                    ~ "GrantedAuthority list instead");
        super.setAuthenticated(false);
    }

    /// Forget the credentials.
    override void eraseCredentials()
    {
        super.eraseCredentials();
        credentials = Any.init;
    }
}

/// The token of an anonymous request (Spring Security's `AnonymousAuthenticationToken`).
class AnonymousAuthenticationToken : AbstractAuthenticationToken
{
    private Any principal;
    private int keyHash;

    /// An anonymous token for `principal`. Throws `IllegalArgumentException` for an empty key or no authorities.
    this(string key, Any principal, GrantedAuthority[] authorities)
    {
        super(authorities);
        if (key.length == 0)
            throw new IllegalArgumentException("key cannot be empty or null");
        if (principal.isNull || (principal.typeName == "string" && principal.get!string.length == 0))
            throw new IllegalArgumentException("principal cannot be null or empty");
        if (authorities.length == 0)
            throw new IllegalArgumentException("authorities cannot be empty");
        keyHash = cast(int) hashOf(key);
        this.principal = principal;
        setAuthenticated(true);
    }

    /// The key's hash.
    int getKeyHash() const pure nothrow @nogc
    {
        return keyHash;
    }

    /// Empty: anonymous tokens have no credentials.
    Any getCredentials()
    {
        return Any.of("");
    }

    /// The principal.
    Any getPrincipal()
    {
        return principal;
    }
}

/// Tells anonymous and remembered tokens apart (Spring Security's `AuthenticationTrustResolver`).
interface AuthenticationTrustResolver
{
    /// Whether `authentication` is anonymous.
    bool isAnonymous(Authentication authentication);
    /// Whether `authentication` was remembered (no remember-me here: false).
    bool isRememberMe(Authentication authentication);
    /// Whether `authentication` is neither anonymous nor remembered.
    bool isFullyAuthenticated(Authentication authentication);
    /// Whether `authentication` is present, authenticated and not anonymous.
    bool isAuthenticated(Authentication authentication);
}

/// Spring Security's `AuthenticationTrustResolverImpl`.
class AuthenticationTrustResolverImpl : AuthenticationTrustResolver
{
    /// Whether an `AnonymousAuthenticationToken`.
    bool isAnonymous(Authentication authentication)
    {
        return authentication !is null && cast(AnonymousAuthenticationToken) authentication !is null;
    }

    /// False.
    bool isRememberMe(Authentication)
    {
        return false;
    }

    /// Whether authenticated, not anonymous and not remembered.
    bool isFullyAuthenticated(Authentication authentication)
    {
        return isAuthenticated(authentication) && !isRememberMe(authentication);
    }

    /// Whether present, authenticated and not anonymous.
    bool isAuthenticated(Authentication authentication)
    {
        return authentication !is null && authentication.isAuthenticated() && !isAnonymous(authentication);
    }
}

/// Thrown for invalid credentials.
class BadCredentialsException : AuthenticationException
{
    /// A failure with `message`.
    this(string message, Throwable cause = null, string file = __FILE__, size_t line = __LINE__) pure nothrow
    {
        super(message, cause, file, line);
    }
}

/// The base of failures caused by the account's status.
abstract class AccountStatusException : AuthenticationException
{
    /// A failure with `message`.
    this(string message, Throwable cause = null, string file = __FILE__, size_t line = __LINE__) pure nothrow
    {
        super(message, cause, file, line);
    }
}

/// Thrown for a disabled account.
class DisabledException : AccountStatusException
{
    /// A failure with `message`.
    this(string message, Throwable cause = null, string file = __FILE__, size_t line = __LINE__) pure nothrow
    {
        super(message, cause, file, line);
    }
}

/// Thrown for a locked account.
class LockedException : AccountStatusException
{
    /// A failure with `message`.
    this(string message, Throwable cause = null, string file = __FILE__, size_t line = __LINE__) pure nothrow
    {
        super(message, cause, file, line);
    }
}

/// Thrown for an expired account.
class AccountExpiredException : AccountStatusException
{
    /// A failure with `message`.
    this(string message, Throwable cause = null, string file = __FILE__, size_t line = __LINE__) pure nothrow
    {
        super(message, cause, file, line);
    }
}

/// Thrown for expired credentials.
class CredentialsExpiredException : AccountStatusException
{
    /// A failure with `message`.
    this(string message, Throwable cause = null, string file = __FILE__, size_t line = __LINE__) pure nothrow
    {
        super(message, cause, file, line);
    }
}

/// Thrown when no provider supports the token.
class ProviderNotFoundException : AuthenticationException
{
    /// A failure with `message`.
    this(string message, Throwable cause = null, string file = __FILE__, size_t line = __LINE__) pure nothrow
    {
        super(message, cause, file, line);
    }
}

/// Thrown when the authentication is not trusted enough.
class InsufficientAuthenticationException : AuthenticationException
{
    /// A failure with `message`.
    this(string message, Throwable cause = null, string file = __FILE__, size_t line = __LINE__) pure nothrow
    {
        super(message, cause, file, line);
    }
}

/// Thrown when no authentication is present.
class AuthenticationCredentialsNotFoundException : AuthenticationException
{
    /// A failure with `message`.
    this(string message, Throwable cause = null, string file = __FILE__, size_t line = __LINE__) pure nothrow
    {
        super(message, cause, file, line);
    }
}

/// Thrown when authentication fails for a system reason.
class InternalAuthenticationServiceException : AuthenticationException
{
    /// A failure with `message`.
    this(string message, Throwable cause = null, string file = __FILE__, size_t line = __LINE__) pure nothrow
    {
        super(message, cause, file, line);
    }
}

/++
Spring Security's `ProviderManager`: asks each provider that supports the token, then the parent; an account-status
or internal failure stops the search. Credentials are erased from the result by default.
+/
class ProviderManager : AuthenticationManager
{
    private AuthenticationProvider[] providers;
    private AuthenticationManager parent;
    private bool eraseCredentialsAfterAuthentication = true;

    /// A manager over `providers`.
    this(AuthenticationProvider[] providers...)
    {
        this(providers.dup, null);
    }

    /// A manager over `providers` with `parent`. Throws `IllegalArgumentException` for a null provider.
    this(AuthenticationProvider[] providers, AuthenticationManager parent)
    {
        foreach (provider; providers)
            if (provider is null)
                throw new IllegalArgumentException("providers list cannot contain null elements");
        if (providers.length == 0 && parent is null)
            throw new IllegalArgumentException(
                    "A parent AuthenticationManager or a list of AuthenticationProviders " ~ "is required");
        this.providers = providers;
        this.parent = parent;
    }

    /// The providers.
    AuthenticationProvider[] getProviders()
    {
        return providers.dup;
    }

    /// Whether to erase credentials from a successful result (default true).
    void setEraseCredentialsAfterAuthentication(bool erase) pure nothrow @nogc
    {
        eraseCredentialsAfterAuthentication = erase;
    }

    /// Authenticate with the first provider that decides, else the parent.
    Authentication authenticate(Authentication authentication)
    {
        const type = authenticationType(authentication);
        AuthenticationException lastException;
        auto result = authenticateWithProviders(authentication, type, lastException);
        if (result is null && parent !is null)
        {
            try
                result = parent.authenticate(authentication);
            catch (ProviderNotFoundException)
            {
            }
            catch (AuthenticationException e)
                lastException = e;
        }
        if (result !is null)
        {
            if (eraseCredentialsAfterAuthentication)
                if (auto container = cast(CredentialsContainer) result)
                    container.eraseCredentials();
            return result;
        }
        if (lastException is null)
            lastException = new ProviderNotFoundException("No AuthenticationProvider found for " ~ type);
        throw lastException;
    }

    /// The first provider's result; an account-status or internal failure is thrown, others are kept in
    /// `lastException`.
    private Authentication authenticateWithProviders(Authentication authentication, string type,
            ref AuthenticationException lastException)
    {
        foreach (provider; providers)
        {
            if (!provider.supports(type))
                continue;
            try
            {
                auto result = provider.authenticate(authentication);
                if (result !is null)
                {
                    copyDetails(authentication, result);
                    return result;
                }
            }
            catch (AccountStatusException e)
            {
                e.setAuthenticationRequest(authentication);
                throw e;
            }
            catch (InternalAuthenticationServiceException e)
            {
                e.setAuthenticationRequest(authentication);
                throw e;
            }
            catch (AuthenticationException e)
            {
                e.setAuthenticationRequest(authentication);
                lastException = e;
            }
        }
        return null;
    }

    private static void copyDetails(Authentication source, Authentication dest)
    {
        auto token = cast(AbstractAuthenticationToken) dest;
        if (token !is null && token.getDetails().isNull)
            token.setDetails(source.getDetails());
    }
}
