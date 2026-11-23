// Ported from spring-security 7.2.0: config/src/main/java/org/springframework/security/config/annotation/authentication
// Copyright 2004-present the original author or authors.
// Licensed under the Apache License, Version 2.0.
// Modified by the Flint authors.
/*
 * Ported from spring-security 7.2.0, config/src/main/java/org/springframework/security/config/annotation/
 * authentication/builders/AuthenticationManagerBuilder.java and authentication/configurers/provisioning/
 * {JdbcUserDetailsManagerConfigurer,InMemoryUserDetailsManagerConfigurer}.java. The builder is not a generic
 * SecurityBuilder; configurers hold their settings and build a DaoAuthenticationProvider each.
 */

/++
`org.springframework.security.config.annotation.authentication.builders`: building the `AuthenticationManager`.
+/
module flint.security.config.annotation.authentication.builders;

import flint.java.lang : IllegalStateException;
import flint.javax.sql : DataSource;
import flint.security.authentication : AuthenticationManager, AuthenticationProvider, ProviderManager;
import flint.security.authentication.dao : DaoAuthenticationProvider;
import flint.security.core.userdetails : UserDetails, UserDetailsService;
import flint.security.core.userdetails.jdbc : JdbcDaoImpl;
import flint.security.crypto.password : PasswordEncoder;
import flint.security.provisioning : InMemoryUserDetailsManager;

@safe:

/// Configures a `JdbcDaoImpl` (Spring Security's `JdbcUserDetailsManagerConfigurer`).
final class JdbcUserDetailsManagerConfigurer
{
    private AuthenticationManagerBuilder builder;
    private JdbcDaoImpl manager;
    private PasswordEncoder encoder;

    private this(AuthenticationManagerBuilder builder)
    {
        this.builder = builder;
        manager = new JdbcDaoImpl;
    }

    /// The data source.
    JdbcUserDetailsManagerConfigurer dataSource(DataSource dataSource)
    {
        manager.setDataSource(dataSource);
        return this;
    }

    /// The users query: user name, password, enabled.
    JdbcUserDetailsManagerConfigurer usersByUsernameQuery(string query)
    {
        manager.setUsersByUsernameQuery(query);
        return this;
    }

    /// The authorities query: user name, authority.
    JdbcUserDetailsManagerConfigurer authoritiesByUsernameQuery(string query)
    {
        manager.setAuthoritiesByUsernameQuery(query);
        return this;
    }

    /// The prefix added to each authority.
    JdbcUserDetailsManagerConfigurer rolePrefix(string rolePrefix)
    {
        manager.setRolePrefix(rolePrefix);
        return this;
    }

    /// The password encoder (else the builder's default).
    JdbcUserDetailsManagerConfigurer passwordEncoder(PasswordEncoder encoder)
    {
        this.encoder = encoder;
        return this;
    }

    /// The builder, to chain further configuration.
    AuthenticationManagerBuilder and()
    {
        return builder;
    }

    private AuthenticationProvider provider(PasswordEncoder defaultEncoder)
    {
        auto dao = new DaoAuthenticationProvider(manager);
        if (auto chosen = encoder is null ? defaultEncoder : encoder)
            dao.setPasswordEncoder(chosen);
        return dao;
    }
}

/// Configures in-memory users (Spring Security's `InMemoryUserDetailsManagerConfigurer`).
final class InMemoryUserDetailsManagerConfigurer
{
    private AuthenticationManagerBuilder builder;
    private InMemoryUserDetailsManager manager;
    private PasswordEncoder encoder;

    private this(AuthenticationManagerBuilder builder)
    {
        this.builder = builder;
        manager = new InMemoryUserDetailsManager;
    }

    /// Add `user`.
    InMemoryUserDetailsManagerConfigurer withUser(UserDetails user)
    {
        manager.createUser(user);
        return this;
    }

    /// The password encoder (else the builder's default).
    InMemoryUserDetailsManagerConfigurer passwordEncoder(PasswordEncoder encoder)
    {
        this.encoder = encoder;
        return this;
    }

    /// The builder.
    AuthenticationManagerBuilder and()
    {
        return builder;
    }

    private AuthenticationProvider provider(PasswordEncoder defaultEncoder)
    {
        auto dao = new DaoAuthenticationProvider(manager);
        if (auto chosen = encoder is null ? defaultEncoder : encoder)
            dao.setPasswordEncoder(chosen);
        return dao;
    }
}

/++
Builds a `ProviderManager` (Spring Security's `AuthenticationManagerBuilder`): JDBC and in-memory user stores, user
details services and providers, in the order configured, with an optional parent. A password encoder supplier
(the context's `PasswordEncoder` bean for the global builder) applies to stores without their own.
+/
class AuthenticationManagerBuilder
{
    private JdbcUserDetailsManagerConfigurer[] jdbc;
    private InMemoryUserDetailsManagerConfigurer[] inMemory;
    private AuthenticationProvider[] providers;
    private AuthenticationManager parent;
    private PasswordEncoder delegate() @safe defaultPasswordEncoder;
    private bool eraseCredentials_ = true;
    private AuthenticationManager built;

    /// A builder whose stores use `defaultPasswordEncoder` (may be null) unless they set their own.
    this(PasswordEncoder delegate() @safe defaultPasswordEncoder = null)
    {
        this.defaultPasswordEncoder = defaultPasswordEncoder;
    }

    /// Add a JDBC user store.
    JdbcUserDetailsManagerConfigurer jdbcAuthentication()
    {
        auto configurer = new JdbcUserDetailsManagerConfigurer(this);
        jdbc ~= configurer;
        return configurer;
    }

    /// Add an in-memory user store.
    InMemoryUserDetailsManagerConfigurer inMemoryAuthentication()
    {
        auto configurer = new InMemoryUserDetailsManagerConfigurer(this);
        inMemory ~= configurer;
        return configurer;
    }

    /// Add a `UserDetailsService` with the default password encoder.
    AuthenticationManagerBuilder userDetailsService(UserDetailsService service)
    {
        auto dao = new DaoAuthenticationProvider(service);
        if (auto encoder = defaultPasswordEncoder is null ? null : defaultPasswordEncoder())
            dao.setPasswordEncoder(encoder);
        providers ~= dao;
        return this;
    }

    /// Add a provider.
    AuthenticationManagerBuilder authenticationProvider(AuthenticationProvider provider)
    {
        providers ~= provider;
        return this;
    }

    /// The parent manager.
    AuthenticationManagerBuilder parentAuthenticationManager(AuthenticationManager parent)
    {
        this.parent = parent;
        return this;
    }

    /// Whether credentials are erased after authentication (default true).
    AuthenticationManagerBuilder eraseCredentials(bool eraseCredentials)
    {
        eraseCredentials_ = eraseCredentials;
        return this;
    }

    /// Whether anything was configured.
    bool isConfigured() const pure nothrow @nogc
    {
        return jdbc.length || inMemory.length || providers.length || parent !is null;
    }

    /// The manager, built once. Throws `IllegalStateException` when nothing is configured.
    AuthenticationManager build()
    {
        if (built !is null)
            return built;
        if (!isConfigured())
            throw new IllegalStateException("This object has not been configured: no AuthenticationProvider, "
                    ~ "UserDetailsService or parent AuthenticationManager");
        auto encoder = defaultPasswordEncoder is null ? null : defaultPasswordEncoder();
        AuthenticationProvider[] all;
        foreach (configurer; jdbc)
            all ~= configurer.provider(encoder);
        foreach (configurer; inMemory)
            all ~= configurer.provider(encoder);
        all ~= providers;
        auto manager = new ProviderManager(all, parent);
        manager.setEraseCredentialsAfterAuthentication(eraseCredentials_);
        built = manager;
        return built;
    }

    /// The built manager, or null before `build`.
    AuthenticationManager getObject() pure nothrow @nogc
    {
        return built;
    }
}
