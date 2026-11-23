/// spring-security-config: petclinic-rest's BasicAuthenticationConfig through HttpSecurity and its configurers.
module app;

import flint.security.config : Customizer;
import flint.security.config.annotation.authentication.builders : AuthenticationManagerBuilder;
import flint.security.config.annotation.web.builders : HttpSecurity;
import flint.security.config.annotation.web.configurers : AuthorizeHttpRequestsConfigurer,
    CsrfConfigurer, HttpBasicConfigurer;
import flint.security.core : AuthorityUtils;
import flint.security.core.userdetails : User;
import flint.security.crypto.password : NoOpPasswordEncoder, PasswordEncoder;
import core.stdc.stdio : fputc, stdout;

@safe:

/// Writes one line without Phobos, so the probe adds no std.format template instances to the module's count.
private void emit(scope const(char)[] text) nothrow @nogc
{
    foreach (c; text)
        fputc(c, stdout);
    fputc('\n', stdout);
}

int main(string[] args)
{
    auto auth = new AuthenticationManagerBuilder(() => cast(PasswordEncoder) NoOpPasswordEncoder.getInstance());
    auth.inMemoryAuthentication().withUser(new User("admin", "admin",
            AuthorityUtils.createAuthorityList("ROLE_ADMIN")));
    auto http = new HttpSecurity(auth.build());
    const secured = args.length <= 1;
    alias Registry = AuthorizeHttpRequestsConfigurer.AuthorizationManagerRequestMatcherRegistry;
    auto chain = http.csrf((CsrfConfigurer csrf) { csrf.disable(); }).authorizeHttpRequests((Registry authz) {
        if (secured)
            authz.anyRequest().authenticated();
        else
            authz.anyRequest().permitAll();
    }).httpBasic(Customizer!HttpBasicConfigurer.withDefaults()).build();
    emit((secured ? "authenticated " : "permitAll ") ~ cast(char)('0' + chain.getFilters().length));
    return 0;
}
