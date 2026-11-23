module flint.security.config_test;

import flint.engine.aot.any : Any;
import flint.jakarta.servlet : FilterChain, ServletRequest, ServletResponse;
import flint.mock.web : MockHttpServletRequest, MockHttpServletResponse;
import flint.security.config : Customizer;
import flint.security.config.annotation.authentication.builders : AuthenticationManagerBuilder;
import flint.security.config.annotation.web.builders : HttpSecurity;
import flint.security.config.annotation.web.configurers : AuthorizeHttpRequestsConfigurer,
    CsrfConfigurer, HeadersConfigurer, HttpBasicConfigurer;
import flint.security.core : Authentication, AuthorityUtils;
import flint.security.core.context : SecurityContextHolder;
import flint.security.core.userdetails : User;
import flint.security.crypto.password : NoOpPasswordEncoder, PasswordEncoder;
import flint.security.web : FilterChainProxy, SecurityFilterChain;

@safe:

private alias Registry = AuthorizeHttpRequestsConfigurer.AuthorizationManagerRequestMatcherRegistry;

/// petclinic-rest's DisableSecurityConfig.filterChain, in Flint.
private SecurityFilterChain disableSecurity(HttpSecurity http)
{
    return http.csrf((CsrfConfigurer csrf) { csrf.disable(); }).authorizeHttpRequests((Registry authz) {
        authz.anyRequest().permitAll();
    }).headers((HeadersConfigurer headers) {
        headers.frameOptions((HeadersConfigurer.FrameOptionsConfig frame) { frame.sameOrigin(); });
    }).build();
}

/// petclinic-rest's BasicAuthenticationConfig.filterChain, in Flint.
private SecurityFilterChain basicAuthentication(HttpSecurity http)
{
    return http.csrf((CsrfConfigurer csrf) { csrf.disable(); }).authorizeHttpRequests((Registry authz) {
        authz.anyRequest().authenticated();
    }).httpBasic(Customizer!HttpBasicConfigurer.withDefaults()).build();
}

private final class Endpoint : FilterChain
{
    bool called;
    Authentication seen;

    void doFilter(ServletRequest, ServletResponse)
    {
        called = true;
        seen = SecurityContextHolder.getContext().getAuthentication();
    }
}

private MockHttpServletResponse run(SecurityFilterChain chain, string method, string authorization, Endpoint endpoint)
{
    auto request = new MockHttpServletRequest(method, "/petclinic/api/owners");
    request.setServletPath("/api/owners");
    if (authorization !is null)
        request.addHeader("Authorization", authorization);
    auto response = new MockHttpServletResponse;
    new FilterChainProxy(chain).doFilter(request, response, endpoint);
    return response;
}

private HttpSecurity httpWithAdmin()
{
    // configureGlobal: in-memory here (the JDBC store reads petclinic's users and roles tables)
    auto auth = new AuthenticationManagerBuilder(() => cast(PasswordEncoder) NoOpPasswordEncoder.getInstance());
    auth.inMemoryAuthentication().withUser(new User("admin", "admin",
            AuthorityUtils.createAuthorityList("ROLE_OWNER_ADMIN", "ROLE_VET_ADMIN", "ROLE_ADMIN")));
    return new HttpSecurity(auth.build());
}

unittest
{
    // DisableSecurityConfig: writes pass without credentials (CSRF off), headers with SAMEORIGIN.
    auto endpoint = new Endpoint;
    auto response = run(disableSecurity(new HttpSecurity), "POST", null, endpoint);
    assert(endpoint.called && endpoint.seen.getName() == "anonymousUser" && response.getStatus() == 200);
    assert(response.getHeader("X-Frame-Options") == "SAMEORIGIN" && response.getHeader("X-XSS-Protection") == "0");
    assert(response.getHeader("X-Content-Type-Options") == "nosniff" && response.getHeader("Expires") == "0");
}

unittest
{
    // BasicAuthenticationConfig: 401 with the Realm challenge without credentials; admin/admin passes; DENY frames.
    auto chain = basicAuthentication(httpWithAdmin());
    auto endpoint = new Endpoint;
    auto response = run(chain, "GET", null, endpoint);
    assert(!endpoint.called && response.getStatus() == 401);
    assert(response.getHeader("WWW-Authenticate") == "Basic realm=\"Realm\"");
    assert(response.getHeader("X-Frame-Options") == "DENY");
    response = run(chain, "POST", "Basic YWRtaW46YWRtaW4=", endpoint);
    assert(endpoint.called && endpoint.seen.getName() == "admin" && response.getStatus() == 200);
}

unittest
{
    // Defaults: CSRF on denies a write with 403; headers can be turned off.
    auto endpoint = new Endpoint;
    auto http = new HttpSecurity;
    http.authorizeHttpRequests((Registry authz) { authz.requestMatchers("/api/**").permitAll(); });
    http.headers((HeadersConfigurer headers) { headers.disable(); });
    auto chain = http.build();
    auto response = run(chain, "POST", null, endpoint);
    assert(!endpoint.called && response.getStatus() == 403 && response.getHeader("X-Frame-Options") is null);
    response = run(chain, "GET", null, endpoint);
    assert(endpoint.called && response.getStatus() == 200);
}
