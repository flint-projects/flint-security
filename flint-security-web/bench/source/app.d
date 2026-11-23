/// spring-security-web: petclinic-rest's HTTP Basic filter chain, assembled into a FilterChainProxy.
module app;

import flint.jakarta.servlet : Filter;
import flint.security.authentication : ProviderManager;
import flint.security.authentication.dao : DaoAuthenticationProvider;
import flint.security.authorization : AuthenticatedAuthorizationManager;
import flint.security.core : AuthorityUtils;
import flint.security.core.userdetails : User;
import flint.security.crypto.password : NoOpPasswordEncoder;
import flint.security.provisioning : InMemoryUserDetailsManager;
import flint.security.web : DefaultSecurityFilterChain, FilterChainProxy;
import flint.security.web.access : AuthorizationFilter, ExceptionTranslationFilter,
    RequestAuthorizationContext, RequestMatcherDelegatingAuthorizationManager;
import flint.security.web.authentication : AnonymousAuthenticationFilter;
import flint.security.web.authentication.www : BasicAuthenticationEntryPoint, BasicAuthenticationFilter;
import flint.security.web.context : RequestAttributeSecurityContextRepository, SecurityContextHolderFilter;
import flint.security.web.header : CacheControlHeadersWriter, HeaderWriterFilter,
    XContentTypeOptionsHeaderWriter, XFrameOptionsHeaderWriter, XXssProtectionHeaderWriter;
import flint.security.web.util.matcher : AnyRequestMatcher;
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
    auto users = new InMemoryUserDetailsManager(new User("admin", "admin",
            AuthorityUtils.createAuthorityList("ROLE_ADMIN")));
    auto provider = new DaoAuthenticationProvider(users);
    provider.setPasswordEncoder(NoOpPasswordEncoder.getInstance());
    auto entryPoint = new BasicAuthenticationEntryPoint;
    entryPoint.setRealmName(args.length > 1 ? "Petclinic" : "Realm");
    auto repository = new RequestAttributeSecurityContextRepository;
    auto basic = new BasicAuthenticationFilter(new ProviderManager(provider), entryPoint);
    basic.setSecurityContextRepository(repository);
    auto rules = new RequestMatcherDelegatingAuthorizationManager;
    rules.add(AnyRequestMatcher.INSTANCE(),
            AuthenticatedAuthorizationManager!RequestAuthorizationContext.authenticated());
    auto frame = new XFrameOptionsHeaderWriter(XFrameOptionsHeaderWriter.XFrameOptionsMode.DENY);
    auto headers = new HeaderWriterFilter(new XContentTypeOptionsHeaderWriter,
            new XXssProtectionHeaderWriter, new CacheControlHeadersWriter, frame);
    auto anonymous = new AnonymousAuthenticationFilter("key");
    auto translation = new ExceptionTranslationFilter(entryPoint);
    Filter[] filters = [
        new SecurityContextHolderFilter(repository), headers, basic, anonymous, translation,
        new AuthorizationFilter(rules)
    ];
    auto proxy = new FilterChainProxy(new DefaultSecurityFilterChain(AnyRequestMatcher.INSTANCE(), filters));
    const count = proxy.getFilterChains()[0].getFilters().length;
    emit(entryPoint.getRealmName() ~ " " ~ cast(char)('0' + count));
    return 0;
}
