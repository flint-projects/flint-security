// Ported from spring-security 7.2.0: config/src/main/java/org/springframework/security/config/annotation/web/configurers
// Copyright 2004-present the original author or authors.
// Licensed under the Apache License, Version 2.0.
// Modified by the Flint authors.
/*
 * Ported from spring-security 7.2.0, config/src/main/java/org/springframework/security/config/annotation/web/
 * configurers/{AbstractHttpConfigurer,CsrfConfigurer,HeadersConfigurer,HttpBasicConfigurer,
 * AuthorizeHttpRequestsConfigurer,AnonymousConfigurer,ExceptionHandlingConfigurer}.java. Configurers keep their
 * settings; HttpSecurity.build() assembles the filters in Spring's FilterOrderRegistration order. Java's nested
 * HeadersConfigurer.FrameOptionsConfig and AuthorizeHttpRequestsConfigurer's registry are nested classes here.
 */

/++
`org.springframework.security.config.annotation.web.configurers`: the parts of `HttpSecurity`.
+/
module flint.security.config.annotation.web.configurers;

import flint.security.authorization : AuthenticatedAuthorizationManager,
    AuthorityAuthorizationManager, AuthorizationManager, SingleResultAuthorizationManager;
import flint.security.config : Customizer;
import flint.security.web : AuthenticationEntryPoint;
import flint.security.web.access : AccessDeniedHandler, RequestAuthorizationContext,
    RequestMatcherDelegatingAuthorizationManager;
import flint.security.web.header : CacheControlHeadersWriter, HeaderWriter, HstsHeaderWriter,
    XContentTypeOptionsHeaderWriter, XFrameOptionsHeaderWriter, XXssProtectionHeaderWriter;
import flint.security.web.util.matcher : AnyRequestMatcher, PathRequestMatcher, RequestMatcher;

@safe:

/// The base of configurers: `disable()` removes the configurer's filters (Spring Security's
/// `AbstractHttpConfigurer`).
abstract class AbstractHttpConfigurer
{
    private bool disabled;

    /// Turn this part off (Java's `AbstractHttpConfigurer::disable` as a customizer).
    void disable() pure nothrow @nogc
    {
        disabled = true;
    }

    /// Whether turned off.
    final bool isDisabled() const pure nothrow @nogc
    {
        return disabled;
    }

    /// Re-enable (a later `csrf(withDefaults())` after `disable`).
    package(flint.security) void enable() pure nothrow @nogc
    {
        disabled = false;
    }
}

/// CSRF protection (Spring Security's `CsrfConfigurer`).
final class CsrfConfigurer : AbstractHttpConfigurer
{
}

/// The anonymous authentication (Spring Security's `AnonymousConfigurer`).
final class AnonymousConfigurer : AbstractHttpConfigurer
{
    private string key_ = "flint-security-anonymous";

    /// The key identifying anonymous tokens.
    AnonymousConfigurer key(string key)
    {
        key_ = key;
        return this;
    }

    /// The key.
    string getKey() const pure nothrow @nogc
    {
        return key_;
    }
}

/// The exception handling (Spring Security's `ExceptionHandlingConfigurer`).
final class ExceptionHandlingConfigurer : AbstractHttpConfigurer
{
    private AuthenticationEntryPoint entryPoint;
    private AccessDeniedHandler deniedHandler;

    /// The entry point for unauthenticated requests.
    ExceptionHandlingConfigurer authenticationEntryPoint(AuthenticationEntryPoint entryPoint)
    {
        this.entryPoint = entryPoint;
        return this;
    }

    /// The handler for denied requests.
    ExceptionHandlingConfigurer accessDeniedHandler(AccessDeniedHandler handler)
    {
        deniedHandler = handler;
        return this;
    }

    /// The configured entry point, or null.
    AuthenticationEntryPoint getAuthenticationEntryPoint() pure nothrow @nogc
    {
        return entryPoint;
    }

    /// The configured handler, or null.
    AccessDeniedHandler getAccessDeniedHandler() pure nothrow @nogc
    {
        return deniedHandler;
    }
}

/// HTTP Basic authentication (Spring Security's `HttpBasicConfigurer`).
final class HttpBasicConfigurer : AbstractHttpConfigurer
{
    private string realm = "Realm";
    private AuthenticationEntryPoint entryPoint;

    /// The realm of the `WWW-Authenticate` challenge (`Realm` by default).
    HttpBasicConfigurer realmName(string realmName)
    {
        realm = realmName;
        return this;
    }

    /// A custom entry point.
    HttpBasicConfigurer authenticationEntryPoint(AuthenticationEntryPoint entryPoint)
    {
        this.entryPoint = entryPoint;
        return this;
    }

    /// The realm.
    string getRealmName() const pure nothrow @nogc
    {
        return realm;
    }

    /// The entry point: the custom one, else Basic with the realm.
    AuthenticationEntryPoint getAuthenticationEntryPoint()
    {
        import flint.security.web.authentication.www : BasicAuthenticationEntryPoint;

        if (entryPoint !is null)
            return entryPoint;
        auto basic = new BasicAuthenticationEntryPoint;
        basic.setRealmName(realm);
        return basic;
    }
}

/// The security response headers (Spring Security's `HeadersConfigurer`).
final class HeadersConfigurer : AbstractHttpConfigurer
{
    /// `X-Frame-Options` (Java's `HeadersConfigurer.FrameOptionsConfig`).
    static final class FrameOptionsConfig
    {
        private XFrameOptionsHeaderWriter.XFrameOptionsMode mode = XFrameOptionsHeaderWriter.XFrameOptionsMode.DENY;
        private bool off;

        /// `DENY` (the default).
        void deny() pure nothrow @nogc
        {
            mode = XFrameOptionsHeaderWriter.XFrameOptionsMode.DENY;
        }

        /// `SAMEORIGIN`.
        void sameOrigin() pure nothrow @nogc
        {
            mode = XFrameOptionsHeaderWriter.XFrameOptionsMode.SAMEORIGIN;
        }

        /// No `X-Frame-Options`.
        void disable() pure nothrow @nogc
        {
            off = true;
        }
    }

    /// A header writer that can be switched off (Java's ContentTypeOptionsConfig, XXssConfig, CacheControlConfig,
    /// HstsConfig).
    static final class WriterConfig
    {
        private bool off;

        /// Turn the header off.
        void disable() pure nothrow @nogc
        {
            off = true;
        }
    }

    private FrameOptionsConfig frame;
    private WriterConfig contentType, xss, cache, hsts;

    /// The default headers.
    this()
    {
        frame = new FrameOptionsConfig;
        contentType = new WriterConfig;
        xss = new WriterConfig;
        cache = new WriterConfig;
        hsts = new WriterConfig;
    }

    /// Customize `X-Frame-Options`.
    HeadersConfigurer frameOptions(Customizer!FrameOptionsConfig customizer)
    {
        customizer.customize(frame);
        return this;
    }

    /// Customize `X-Frame-Options` with a lambda.
    HeadersConfigurer frameOptions(void delegate(FrameOptionsConfig) @safe customizer)
    {
        customizer(frame);
        return this;
    }

    /// Customize `X-Content-Type-Options`.
    HeadersConfigurer contentTypeOptions(void delegate(WriterConfig) @safe customizer)
    {
        customizer(contentType);
        return this;
    }

    /// Customize `X-XSS-Protection`.
    HeadersConfigurer xssProtection(void delegate(WriterConfig) @safe customizer)
    {
        customizer(xss);
        return this;
    }

    /// Customize the cache headers.
    HeadersConfigurer cacheControl(void delegate(WriterConfig) @safe customizer)
    {
        customizer(cache);
        return this;
    }

    /// Customize `Strict-Transport-Security`.
    HeadersConfigurer httpStrictTransportSecurity(void delegate(WriterConfig) @safe customizer)
    {
        customizer(hsts);
        return this;
    }

    /// The writers, in Spring's order: content type options, XSS, cache control, HSTS, frame options.
    HeaderWriter[] getHeaderWriters()
    {
        HeaderWriter[] writers;
        if (!contentType.off)
            writers ~= new XContentTypeOptionsHeaderWriter;
        if (!xss.off)
            writers ~= new XXssProtectionHeaderWriter;
        if (!cache.off)
            writers ~= new CacheControlHeadersWriter;
        if (!hsts.off)
            writers ~= new HstsHeaderWriter;
        if (!frame.off)
            writers ~= new XFrameOptionsHeaderWriter(frame.mode);
        return writers;
    }
}

/// Request authorization rules (Spring Security's `AuthorizeHttpRequestsConfigurer`).
final class AuthorizeHttpRequestsConfigurer : AbstractHttpConfigurer
{
    /// The rules, in order (Java's `AuthorizationManagerRequestMatcherRegistry`).
    static final class AuthorizationManagerRequestMatcherRegistry
    {
        private RequestMatcherDelegatingAuthorizationManager manager;
        private size_t rules;

        private this()
        {
            manager = new RequestMatcherDelegatingAuthorizationManager;
        }

        /// Every request.
        AuthorizedUrl anyRequest()
        {
            return new AuthorizedUrl(this, AnyRequestMatcher.INSTANCE());
        }

        /// Requests whose path matches any of `patterns` (`/api/**`).
        AuthorizedUrl requestMatchers(string[] patterns...)
        {
            return new AuthorizedUrl(this, new AnyOf(patterns.dup));
        }

        /// The rules' manager.
        RequestMatcherDelegatingAuthorizationManager getManager() pure nothrow @nogc
        {
            return manager;
        }

        /// How many rules were added.
        size_t size() const pure nothrow @nogc
        {
            return rules;
        }

        private AuthorizationManagerRequestMatcherRegistry add(RequestMatcher matcher,
                AuthorizationManager!RequestAuthorizationContext authorization)
        {
            manager.add(matcher, authorization);
            rules++;
            return this;
        }
    }

    /// The access for the matched requests (Java's `AuthorizedUrl`).
    static final class AuthorizedUrl
    {
        private alias Context = RequestAuthorizationContext;
        private AuthorizationManagerRequestMatcherRegistry registry;
        private RequestMatcher matcher;

        private this(AuthorizationManagerRequestMatcherRegistry registry, RequestMatcher matcher)
        {
            this.registry = registry;
            this.matcher = matcher;
        }

        /// Everyone.
        AuthorizationManagerRequestMatcherRegistry permitAll()
        {
            return registry.add(matcher, SingleResultAuthorizationManager!Context.permitAll());
        }

        /// No one.
        AuthorizationManagerRequestMatcherRegistry denyAll()
        {
            return registry.add(matcher, SingleResultAuthorizationManager!Context.denyAll());
        }

        /// Authenticated, non-anonymous principals.
        AuthorizationManagerRequestMatcherRegistry authenticated()
        {
            return registry.add(matcher, AuthenticatedAuthorizationManager!Context.authenticated());
        }

        /// Anonymous principals.
        AuthorizationManagerRequestMatcherRegistry anonymous()
        {
            return registry.add(matcher, AuthenticatedAuthorizationManager!Context.anonymous_());
        }

        /// Principals with `ROLE_<role>`.
        AuthorizationManagerRequestMatcherRegistry hasRole(string role)
        {
            return registry.add(matcher, AuthorityAuthorizationManager!Context.hasRole(role));
        }

        /// Principals with any of the roles.
        AuthorizationManagerRequestMatcherRegistry hasAnyRole(string[] roles...)
        {
            return registry.add(matcher, AuthorityAuthorizationManager!Context.hasAnyRole(roles));
        }

        /// Principals with `authority`.
        AuthorizationManagerRequestMatcherRegistry hasAuthority(string authority)
        {
            return registry.add(matcher, AuthorityAuthorizationManager!Context.hasAuthority(authority));
        }

        /// Principals with any of the authorities.
        AuthorizationManagerRequestMatcherRegistry hasAnyAuthority(string[] authorities...)
        {
            return registry.add(matcher, AuthorityAuthorizationManager!Context.hasAnyAuthority(authorities));
        }
    }

    private AuthorizationManagerRequestMatcherRegistry registry_;

    /// An empty rule set.
    this()
    {
        registry_ = new AuthorizationManagerRequestMatcherRegistry;
    }

    /// The registry the customizer fills.
    AuthorizationManagerRequestMatcherRegistry getRegistry() pure nothrow @nogc
    {
        return registry_;
    }
}

/// Matches when any of the path patterns does.
private final class AnyOf : RequestMatcher
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
