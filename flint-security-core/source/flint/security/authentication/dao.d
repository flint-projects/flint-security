// Ported from spring-security 7.2.0: core/src/main/java/org/springframework/security/authentication/dao
// Copyright 2004-present the original author or authors.
// Licensed under the Apache License, Version 2.0.
// Modified by the Flint authors.
/*
 * Ported from spring-security 7.2.0, core/src/main/java/org/springframework/security/authentication/dao/{
 * AbstractUserDetailsAuthenticationProvider,DaoAuthenticationProvider}.java. The user cache, password upgrading and
 * the timing-attack mitigation's dummy encode are not ported (the mitigation needs the password encoder's real cost,
 * which BCrypt's pending provider would give).
 */

/++
`org.springframework.security.authentication.dao`: user-name and password authentication over a
`UserDetailsService`.
+/
module flint.security.authentication.dao;

import flint.engine.aot.any : Any;
import flint.engine.aot.name : typeNameOf;
import flint.java.lang : IllegalArgumentException;
import flint.security.authentication : AccountExpiredException, AuthenticationProvider,
    BadCredentialsException, CredentialsExpiredException,
    DisabledException, InternalAuthenticationServiceException, LockedException, UsernamePasswordAuthenticationToken;
import flint.security.core : Authentication;
import flint.security.core.userdetails : UserDetails, UserDetailsService, UsernameNotFoundException;
import flint.security.crypto.factory : PasswordEncoderFactories;
import flint.security.crypto.password : PasswordEncoder;

@safe:

/// Spring Security's `DaoAuthenticationProvider`: loads the user, checks its account and its password.
class DaoAuthenticationProvider : AuthenticationProvider
{
    private UserDetailsService userDetailsService;
    private PasswordEncoder passwordEncoder;
    private bool hideUserNotFoundExceptions = true;

    /// A provider with a delegating password encoder.
    this()
    {
        passwordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    /// A provider over `userDetailsService`.
    this(UserDetailsService userDetailsService)
    {
        this();
        this.userDetailsService = userDetailsService;
    }

    /// Set the users.
    void setUserDetailsService(UserDetailsService userDetailsService) pure nothrow @nogc
    {
        this.userDetailsService = userDetailsService;
    }

    /// Set the password encoder. Throws `IllegalArgumentException` for null.
    void setPasswordEncoder(PasswordEncoder passwordEncoder)
    {
        if (passwordEncoder is null)
            throw new IllegalArgumentException("passwordEncoder cannot be null");
        this.passwordEncoder = passwordEncoder;
    }

    /// Report an unknown user as bad credentials (default true).
    void setHideUserNotFoundExceptions(bool hide) pure nothrow @nogc
    {
        hideUserNotFoundExceptions = hide;
    }

    /// Only `UsernamePasswordAuthenticationToken`.
    bool supports(string authenticationType)
    {
        return authenticationType == typeNameOf!UsernamePasswordAuthenticationToken;
    }

    /// The authenticated token for a valid user name and password.
    Authentication authenticate(Authentication authentication)
    {
        auto token = cast(UsernamePasswordAuthenticationToken) authentication;
        if (token is null)
            throw new IllegalArgumentException("Only UsernamePasswordAuthenticationToken is supported");
        const username = token.getPrincipal().isNull ? "NONE_PROVIDED" : token.getName();
        UserDetails user;
        try
            user = retrieveUser(username);
        catch (UsernameNotFoundException e)
        {
            if (hideUserNotFoundExceptions)
                throw new BadCredentialsException("Bad credentials");
            throw e;
        }
        preAuthenticationChecks(user);
        additionalAuthenticationChecks(user, token);
        postAuthenticationChecks(user);
        auto result = UsernamePasswordAuthenticationToken.authenticated(Any.of(cast(Object) user),
                token.getCredentials(), user.getAuthorities());
        result.setDetails(token.getDetails());
        return result;
    }

    /// The user named `username`. Throws `UsernameNotFoundException`, or `InternalAuthenticationServiceException`
    /// when the service returns null or fails.
    protected UserDetails retrieveUser(string username)
    {
        UserDetails loaded;
        try
            loaded = userDetailsService.loadUserByUsername(username);
        catch (UsernameNotFoundException e)
            throw e;
        catch (InternalAuthenticationServiceException e)
            throw e;
        catch (Exception e)
            throw new InternalAuthenticationServiceException(e.msg, e);
        if (loaded is null)
            throw new InternalAuthenticationServiceException(
                    "UserDetailsService returned null, which is an interface contract violation");
        return loaded;
    }

    /// The password check. Throws `BadCredentialsException`.
    protected void additionalAuthenticationChecks(UserDetails user, UsernamePasswordAuthenticationToken token)
    {
        auto credentials = token.getCredentials();
        if (credentials.isNull || credentials.typeName != "string")
            throw new BadCredentialsException("Bad credentials");
        if (!passwordEncoder.matches(credentials.get!string, user.getPassword()))
            throw new BadCredentialsException("Bad credentials");
    }

    private static void preAuthenticationChecks(UserDetails user)
    {
        if (!user.isAccountNonLocked())
            throw new LockedException("User account is locked");
        if (!user.isEnabled())
            throw new DisabledException("User is disabled");
        if (!user.isAccountNonExpired())
            throw new AccountExpiredException("User account has expired");
    }

    private static void postAuthenticationChecks(UserDetails user)
    {
        if (!user.isCredentialsNonExpired())
            throw new CredentialsExpiredException("User credentials have expired");
    }
}
