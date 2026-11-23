// Ported from spring-security 7.2.0: config/src/main/java/org/springframework/security/config/annotation/web/builders/HttpSecurity.java
// Copyright 2004-present the original author or authors.
// Licensed under the Apache License, Version 2.0.
// Modified by the Flint authors.
/*
 * The builder keeps one configurer per part and assembles the filters in Spring's FilterOrderRegistration order.
 * Customizers are Customizer!T or a lambda. Not ported: form login, logout, sessions, the request cache, CORS,
 * remember-me, OAuth2 and SAML, addFilterBefore/After.
 */

/++
`org.springframework.security.config.annotation.web.builders`: the `HttpSecurity` DSL.
+/
module flint.security.config.annotation.web.builders;

import flint.jakarta.servlet : Filter;
import flint.security.authentication : AuthenticationManager;
import flint.security.config : Customizer;
import flint.security.config.annotation.web.configurers : AnonymousConfigurer, AuthorizeHttpRequestsConfigurer,
    CsrfConfigurer, ExceptionHandlingConfigurer, HeadersConfigurer, HttpBasicConfigurer;
import flint.security.web : AuthenticationEntryPoint, DefaultSecurityFilterChain, SecurityFilterChain;
import flint.security.web.access : AuthorizationFilter, ExceptionTranslationFilter;
import flint.security.web.authentication : AnonymousAuthenticationFilter, Http403ForbiddenEntryPoint;
import flint.security.web.authentication.www : BasicAuthenticationFilter;
import flint.security.web.context : RequestAttributeSecurityContextRepository, SecurityContextHolderFilter;
import flint.security.web.csrf : CsrfFilter;
import flint.security.web.header : HeaderWriterFilter;
import flint.security.web.util.matcher : AnyRequestMatcher, PathRequestMatcher, RequestMatcher;

@safe:

/// Configures the security of HTTP requests and builds a `SecurityFilterChain` (Spring Security's `HttpSecurity`).
final class HttpSecurity
{
    private CsrfConfigurer csrf_;
    private HeadersConfigurer headers_;
    private AnonymousConfigurer anonymous_;
    private ExceptionHandlingConfigurer exceptionHandling_;
    private HttpBasicConfigurer httpBasic_;
    private AuthorizeHttpRequestsConfigurer authorize_;
    private AuthenticationManager authenticationManager_;
    private RequestMatcher securityMatcher_;

    /// A builder with Spring's defaults (CSRF, headers, anonymous, exception handling) and the shared manager.
    this(AuthenticationManager sharedAuthenticationManager = null)
    {
        csrf_ = new CsrfConfigurer;
        headers_ = new HeadersConfigurer;
        anonymous_ = new AnonymousConfigurer;
        exceptionHandling_ = new ExceptionHandlingConfigurer;
        authenticationManager_ = sharedAuthenticationManager;
        securityMatcher_ = AnyRequestMatcher.INSTANCE();
    }

    /// Customize CSRF protection (`csrf(AbstractHttpConfigurer::disable)` is `csrf((CsrfConfigurer c) => c.disable())`).
    HttpSecurity csrf(void delegate(CsrfConfigurer) @safe customizer)
    {
        csrf_.enable();
        customizer(csrf_);
        return this;
    }

    /// Customize CSRF protection.
    HttpSecurity csrf(Customizer!CsrfConfigurer customizer)
    {
        return csrf(&customizer.customize);
    }

    /// Customize the response headers.
    HttpSecurity headers(void delegate(HeadersConfigurer) @safe customizer)
    {
        headers_.enable();
        customizer(headers_);
        return this;
    }

    /// Customize the response headers.
    HttpSecurity headers(Customizer!HeadersConfigurer customizer)
    {
        return headers(&customizer.customize);
    }

    /// Customize anonymous authentication.
    HttpSecurity anonymous(void delegate(AnonymousConfigurer) @safe customizer)
    {
        anonymous_.enable();
        customizer(anonymous_);
        return this;
    }

    /// Customize anonymous authentication.
    HttpSecurity anonymous(Customizer!AnonymousConfigurer customizer)
    {
        return anonymous(&customizer.customize);
    }

    /// Customize exception handling.
    HttpSecurity exceptionHandling(void delegate(ExceptionHandlingConfigurer) @safe customizer)
    {
        customizer(exceptionHandling_);
        return this;
    }

    /// Customize exception handling.
    HttpSecurity exceptionHandling(Customizer!ExceptionHandlingConfigurer customizer)
    {
        return exceptionHandling(&customizer.customize);
    }

    /// Enable HTTP Basic authentication.
    HttpSecurity httpBasic(void delegate(HttpBasicConfigurer) @safe customizer)
    {
        if (httpBasic_ is null)
            httpBasic_ = new HttpBasicConfigurer;
        customizer(httpBasic_);
        return this;
    }

    /// Enable HTTP Basic authentication (`httpBasic(Customizer.withDefaults())`).
    HttpSecurity httpBasic(Customizer!HttpBasicConfigurer customizer)
    {
        return httpBasic(&customizer.customize);
    }

    /// Authorize requests by rules.
    HttpSecurity authorizeHttpRequests(void delegate(
            AuthorizeHttpRequestsConfigurer.AuthorizationManagerRequestMatcherRegistry) @safe customizer)
    {
        if (authorize_ is null)
            authorize_ = new AuthorizeHttpRequestsConfigurer;
        customizer(authorize_.getRegistry());
        return this;
    }

    /// Authorize requests by rules.
    HttpSecurity authorizeHttpRequests(Customizer!(
            AuthorizeHttpRequestsConfigurer.AuthorizationManagerRequestMatcherRegistry) customizer)
    {
        return authorizeHttpRequests(&customizer.customize);
    }

    /// Use `authenticationManager` instead of the shared one.
    HttpSecurity authenticationManager(AuthenticationManager authenticationManager)
    {
        authenticationManager_ = authenticationManager;
        return this;
    }

    /// Limit this chain to requests whose path matches any of `patterns`.
    HttpSecurity securityMatcher(string[] patterns...)
    {
        securityMatcher_ = new AnyPattern(patterns.dup);
        return this;
    }

    /// The chain: context, headers, CSRF, Basic, anonymous, exception translation, authorization.
    SecurityFilterChain build()
    {
        auto repository = new RequestAttributeSecurityContextRepository;
        Filter[] filters = [new SecurityContextHolderFilter(repository)];
        if (!headers_.isDisabled())
            filters ~= new HeaderWriterFilter(headers_.getHeaderWriters());
        if (!csrf_.isDisabled())
            filters ~= new CsrfFilter;
        if (httpBasic_ !is null && !httpBasic_.isDisabled())
        {
            auto basic = new BasicAuthenticationFilter(requireAuthenticationManager(),
                    httpBasic_.getAuthenticationEntryPoint());
            basic.setSecurityContextRepository(repository);
            filters ~= basic;
        }
        if (!anonymous_.isDisabled())
            filters ~= new AnonymousAuthenticationFilter(anonymous_.getKey());
        if (!exceptionHandling_.isDisabled())
        {
            auto translation = new ExceptionTranslationFilter(entryPoint());
            if (auto handler = exceptionHandling_.getAccessDeniedHandler())
                translation.setAccessDeniedHandler(handler);
            filters ~= translation;
        }
        if (authorize_ !is null && !authorize_.isDisabled())
            filters ~= new AuthorizationFilter(authorize_.getRegistry().getManager());
        return new DefaultSecurityFilterChain(securityMatcher_, filters);
    }

    private AuthenticationEntryPoint entryPoint()
    {
        if (auto configured = exceptionHandling_.getAuthenticationEntryPoint())
            return configured;
        if (httpBasic_ !is null && !httpBasic_.isDisabled())
            return httpBasic_.getAuthenticationEntryPoint();
        return new Http403ForbiddenEntryPoint;
    }

    private AuthenticationManager requireAuthenticationManager()
    {
        import flint.java.lang : IllegalStateException;

        if (authenticationManager_ is null)
            throw new IllegalStateException("httpBasic() needs an AuthenticationManager");
        return authenticationManager_;
    }
}

/// Matches when any of the path patterns does.
private final class AnyPattern : RequestMatcher
{
    import flint.jakarta.servlet.http : HttpServletRequest;

    private RequestMatcher[] matchers;

    this(string[] patterns)
    {
        foreach (pattern; patterns)
            matchers ~= new PathRequestMatcher(pattern);
    }

    bool matches(HttpServletRequest request)
    {
        foreach (matcher; matchers)
            if (matcher.matches(request))
                return true;
        return false;
    }
}
