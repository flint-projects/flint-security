// Ported from spring-security 7.2.0: config/src/main/java/org/springframework/security/config/annotation/authentication/configuration/AuthenticationConfiguration.java
// Copyright 2004-present the original author or authors.
// Licensed under the Apache License, Version 2.0.
// Modified by the Flint authors.
/*
 * The global AuthenticationManagerBuilder takes the context's PasswordEncoder bean lazily, as Spring's
 * DefaultPasswordEncoderAuthenticationManagerBuilder does. Without a configured builder, the manager comes from a
 * single UserDetailsService bean (InitializeUserDetailsBeanManagerConfigurer) or AuthenticationProvider bean
 * (InitializeAuthenticationProviderBeanManagerConfigurer). The manager is built on first use.
 */

/++
`org.springframework.security.config.annotation.authentication.configuration`: the global `AuthenticationManager`.
+/
module flint.security.config.annotation.authentication.configuration;

import flint.beans.factory : ListableBeanFactory;
import flint.context : ApplicationContext;
import flint.context.annotation : Bean, Configuration;
import flint.engine.aot.name : typeNameOf;
import flint.security.authentication : AuthenticationManager, AuthenticationProvider, ProviderManager;
import flint.security.authentication.dao : DaoAuthenticationProvider;
import flint.security.config.annotation.authentication.builders : AuthenticationManagerBuilder;
import flint.security.core : Authentication;
import flint.security.core.userdetails : UserDetailsService;
import flint.security.crypto.password : PasswordEncoder;

@safe:

/// Exports the global `AuthenticationManagerBuilder` and builds the manager from it (Spring Security's
/// `AuthenticationConfiguration`).
@Configuration(proxyBeanMethods: false)
class AuthenticationConfiguration
{
    private ApplicationContext context;
    private AuthenticationManagerBuilder builder;
    private AuthenticationManager manager;

    /// A configuration over `context`.
    this(ApplicationContext context)
    {
        this.context = context;
    }

    /// The global builder, configured by `@Autowired configureGlobal(AuthenticationManagerBuilder)` methods.
    @Bean
    AuthenticationManagerBuilder authenticationManagerBuilder()
    {
        if (builder is null)
            builder = new AuthenticationManagerBuilder(&passwordEncoderBean);
        return builder;
    }

    /// The global manager, built on first use; null when there is nothing to authenticate with.
    AuthenticationManager getAuthenticationManager()
    {
        if (manager !is null)
            return manager;
        auto configured = authenticationManagerBuilder();
        if (configured.isConfigured())
            return manager = configured.build();
        if (auto service = single!UserDetailsService())
        {
            auto dao = new DaoAuthenticationProvider(service);
            if (auto encoder = passwordEncoderBean())
                dao.setPasswordEncoder(encoder);
            return manager = new ProviderManager(dao);
        }
        if (auto provider = single!AuthenticationProvider())
            return manager = new ProviderManager(provider);
        return null;
    }

    /// The context's `PasswordEncoder` bean, or null.
    private PasswordEncoder passwordEncoderBean()
    {
        return single!PasswordEncoder();
    }

    private T single(T)()
    {
        auto names = context.getBeanNamesForTypeErased(typeNameOf!T, true, false);
        return names.length == 1 ? cast(T) context.getBean(names[0]) : null;
    }
}

/// An `AuthenticationManager` that asks `AuthenticationConfiguration` on first use, so the filter chain can be
/// built before the global builder is configured.
final class LazyAuthenticationManager : AuthenticationManager
{
    private AuthenticationManager delegate() @safe supplier;

    /// A manager resolved by `supplier`.
    this(AuthenticationManager delegate() @safe supplier)
    {
        this.supplier = supplier;
    }

    /// Authenticate with the resolved manager. Throws `IllegalStateException` when there is none.
    Authentication authenticate(Authentication authentication)
    {
        import flint.java.lang : IllegalStateException;

        auto resolved = supplier();
        if (resolved is null)
            throw new IllegalStateException("No AuthenticationManager is configured: declare a UserDetailsService, "
                    ~ "an AuthenticationProvider or configure the AuthenticationManagerBuilder");
        return resolved.authenticate(authentication);
    }
}
