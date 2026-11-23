// Ported from spring-security 7.2.0: config/src/main/java/org/springframework/security/config/annotation/method/configuration
// Copyright 2004-present the original author or authors.
// Licensed under the Apache License, Version 2.0.
// Modified by the Flint authors.
/*
 * Ported from spring-security 7.2.0, config/src/main/java/org/springframework/security/config/annotation/method/
 * configuration/{EnableMethodSecurity,PrePostMethodSecurityConfiguration}.java. @Secured and JSR-250 are not ported;
 * @PostAuthorize and the filters wait for their interceptors.
 */

/++
`org.springframework.security.config.annotation.method.configuration`: `@EnableMethodSecurity`.
+/
module flint.security.config.annotation.method.configuration;

import flint.context : ApplicationContext;
import flint.context.annotation : Bean, Configuration, Import;
import flint.core.annotation : classOf;
import flint.security.authorization.method : PreAuthorizeMethodInterceptor;

@safe:

/// Registers the `@PreAuthorize` advisor (Spring Security's `PrePostMethodSecurityConfiguration`).
@Configuration(proxyBeanMethods: false)
class PrePostMethodSecurityConfiguration
{
    /// The advisor that authorizes `@PreAuthorize` methods before they run.
    @Bean
    PreAuthorizeMethodInterceptor preAuthorizeAuthorizationMethodInterceptor(ApplicationContext context)
    {
        return new PreAuthorizeMethodInterceptor(context);
    }
}

/// Enable method security: `@PreAuthorize` through the advisor (Spring Security's `@EnableMethodSecurity`).
@Import([classOf!PrePostMethodSecurityConfiguration])
struct EnableMethodSecurity
{
    /// Whether `@PreAuthorize` and `@PostAuthorize` are enabled.
    bool prePostEnabled = true;
    /// Whether `@Secured` is enabled (not ported).
    bool securedEnabled;
    /// Whether JSR-250 annotations are enabled (not ported).
    bool jsr250Enabled;
}
