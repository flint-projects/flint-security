/// spring-security-core: DaoAuthenticationProvider over an InMemoryUserDetailsManager, behind a ProviderManager.
module app;

import flint.engine.aot.any : Any;
import flint.security.authentication : ProviderManager, UsernamePasswordAuthenticationToken;
import flint.security.authentication.dao : DaoAuthenticationProvider;
import flint.security.core : AuthorityUtils;
import flint.security.core.userdetails : User;
import flint.security.crypto.password : NoOpPasswordEncoder;
import flint.security.provisioning : InMemoryUserDetailsManager;
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
    auto rod = new User("rod", "koala", AuthorityUtils.createAuthorityList("ROLE_ONE", "ROLE_TWO"));
    auto joe = new User("joe", "opal", AuthorityUtils.createAuthorityList("ROLE_ONE"));
    auto users = new InMemoryUserDetailsManager(rod, joe);
    auto provider = new DaoAuthenticationProvider(users);
    provider.setPasswordEncoder(NoOpPasswordEncoder.getInstance());
    const name = args.length > 1 ? "joe" : "rod";
    const password = args.length > 1 ? "opal" : "koala";
    auto result = new ProviderManager(provider).authenticate(
            UsernamePasswordAuthenticationToken.unauthenticated(Any.of(name), Any.of(password)));
    emit(result.getName() ~ " " ~ cast(char)('0' + result.getAuthorities().length));
    return 0;
}
