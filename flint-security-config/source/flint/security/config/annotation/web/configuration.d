// Ported from spring-security 7.2.0: config/src/main/java/org/springframework/security/config/annotation/web/configuration
// Copyright 2004-present the original author or authors.
// Licensed under the Apache License, Version 2.0.
// Modified by the Flint authors.
/*
 * Ported from spring-security 7.2.0, config/src/main/java/org/springframework/security/config/annotation/web/
 * configuration/{EnableWebSecurity,WebSecurityConfiguration,HttpSecurityConfiguration}.java. WebSecurity's ignoring
 * and debug are not ported; without SecurityFilterChain beans the default chain is authenticated requests with
 * HTTP Basic (Spring adds form login, which is not ported).
 */

/++
`org.springframework.security.config.annotation.web.configuration`: `@EnableWebSecurity` and its configurations.
+/
module flint.security.config.annotation.web.configuration;

import flint.context.annotation : Bean, Configuration, Import, Scope;
import flint.core.annotation : classOf;
import flint.jakarta.servlet : Filter;
import flint.security.config : Customizer;
import flint.security.config.annotation.authentication.configuration : AuthenticationConfiguration,
    LazyAuthenticationManager;
import flint.security.config.annotation.web.builders : HttpSecurity;
import flint.security.config.annotation.web.configurers : AuthorizeHttpRequestsConfigurer, HttpBasicConfigurer;
import flint.security.web : FilterChainProxy, SecurityFilterChain;

@safe:

/// Provides the prototype `HttpSecurity` with Spring's defaults (Spring Security's `HttpSecurityConfiguration`).
@Configuration(proxyBeanMethods: false)
class HttpSecurityConfiguration
{
    /// A new `HttpSecurity` for each `SecurityFilterChain` bean, sharing the global authentication manager.
    @Bean
    @Scope("prototype")
    HttpSecurity httpSecurity(AuthenticationConfiguration authenticationConfiguration)
    {
        return new HttpSecurity(new LazyAuthenticationManager(&authenticationConfiguration.getAuthenticationManager));
    }
}

/// Exports `springSecurityFilterChain`, the `FilterChainProxy` over the `SecurityFilterChain` beans (Spring
/// Security's `WebSecurityConfiguration`).
@Configuration(proxyBeanMethods: false)
class WebSecurityConfiguration
{
    /// The bean name Boot registers as the servlet filter.
    enum DEFAULT_FILTER_NAME = "springSecurityFilterChain";

    /// The proxy over `securityFilterChains`; without any, a default chain from `http`.
    @Bean(["springSecurityFilterChain"])
    Filter springSecurityFilterChain(SecurityFilterChain[] securityFilterChains, HttpSecurity http)
    {
        if (securityFilterChains.length == 0)
            securityFilterChains = [defaultChain(http)];
        return new FilterChainProxy(securityFilterChains);
    }

    private static SecurityFilterChain defaultChain(HttpSecurity http)
    {
        alias Registry = AuthorizeHttpRequestsConfigurer.AuthorizationManagerRequestMatcherRegistry;
        return http.authorizeHttpRequests((Registry authorize) {
            authorize.anyRequest().authenticated();
        }).httpBasic(Customizer!HttpBasicConfigurer.withDefaults()).build();
    }
}

/// Enable Spring Security's web support: imports `WebSecurityConfiguration`, `HttpSecurityConfiguration` and
/// `AuthenticationConfiguration` (Spring Security's `@EnableWebSecurity`).
@Import([
    classOf!WebSecurityConfiguration, classOf!HttpSecurityConfiguration,
    classOf!AuthenticationConfiguration
])
struct EnableWebSecurity
{
    /// Whether to log security debugging information (not ported: ignored).
    bool debug_;
}
