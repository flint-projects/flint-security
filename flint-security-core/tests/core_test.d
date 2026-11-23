// Ported from spring-security 7.2.0: core/src/test/java/org/springframework/security
/*
 * Copyright 2004-present the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Modified by the Flint authors: ported from spring-security 7.2.0,
 * core/src/test/java/org/springframework/security/{core/userdetails/UserTests,authentication/ProviderManagerTests,
 * authentication/dao/DaoAuthenticationProviderTests,authorization/AuthorityAuthorizationManagerTests,
 * provisioning/InMemoryUserDetailsManagerTests,core/authority/SimpleGrantedAuthorityTests}.java.
 */

/++
Spring Security core: users, the provider manager, the DAO provider, authority decisions, the fiber-local context
and the `@PreAuthorize` interceptor over a compiled expression. Each unittest names the Java tests it covers; the
Java classes' remaining tests exercise Jackson serialization, events, user caches, message sources and Mockito
interactions that have no Flint counterpart yet.
+/
module flint.security.core_test;

import flint.engine.aot.any : Any;
import flint.engine.aot.name : typeNameOf;
import flint.java.lang : IllegalArgumentException, valueOf;
import flint.security.authentication : AuthenticationManager, AuthenticationProvider,
    BadCredentialsException, DisabledException,
    LockedException, ProviderManager, ProviderNotFoundException, UsernamePasswordAuthenticationToken;
import flint.security.authentication.dao : DaoAuthenticationProvider;
import flint.security.authorization : AuthorityAuthorizationManager, AuthorizationDeniedException;
import flint.security.core : Authentication, AuthorityUtils, GrantedAuthority, SimpleGrantedAuthority;
import flint.security.core.context : SecurityContextHolder, SecurityContextImpl;
import flint.security.core.userdetails : User, UserDetails, UsernameNotFoundException;
import flint.security.crypto.password : NoOpPasswordEncoder;
import flint.security.provisioning : InMemoryUserDetailsManager;
import std.exception : collectException;

@safe:

private GrantedAuthority[] roles(string[] names...)
{
    return AuthorityUtils.createAuthorityList(names);
}

unittest
{
    // UserTests: equalsReturnsTrueIfUsernamesAreTheSame, testNullValuesRejected, hashLookupOnlyDependsOnUsername,
    // testUserGettersSetter, enabledFlagIsFalseForDisabledAccount, toStringSkipsPassword, authoritiesSorted,
    // duplicateAuthoritiesRemoved, roles...
    auto user = new User("rod", "koala", roles("ROLE_TWO", "ROLE_ONE"));
    assert(user == new User("rod", "other", roles("ROLE_X")));
    assert(user.toHash() == new User("rod", "x", null).toHash());
    assert(collectException!IllegalArgumentException(new User("", "koala", null)) !is null);
    assert(collectException!IllegalArgumentException(new User(null, "koala", null)) !is null);
    assert(user.getAuthorities()[0].getAuthority() == "ROLE_ONE");
    assert(user.getAuthorities()[1].getAuthority() == "ROLE_TWO");
    assert(new User("rod", "koala", roles("ROLE_A", "ROLE_A")).getAuthorities().length == 1);
    assert(!new User("rod", "koala", false, true, true, true, null).isEnabled());
    const text = user.toString();
    assert(text == "flint.security.core.userdetails.User [Username=rod, Password=[PROTECTED], Enabled=true, "
            ~ "AccountNonExpired=true, CredentialsNonExpired=true, AccountNonLocked=true, "
            ~ "Granted Authorities=[ROLE_ONE, ROLE_TWO]]");
    auto built = User.withUsername("joe").password("pw").roles("USER", "ADMIN").build();
    assert(built.getAuthorities()[0].getAuthority() == "ROLE_ADMIN" && built.getPassword() == "pw");
    assert(collectException!IllegalArgumentException(User.withUsername("joe").roles("ROLE_USER")) !is null);
    user.eraseCredentials();
    assert(user.getPassword() is null);
}

unittest
{
    // SimpleGrantedAuthorityTests: equalsBehavesAsExpected, toStringReturnsAuthorityValue
    assert(new SimpleGrantedAuthority("ROLE_A") == new SimpleGrantedAuthority("ROLE_A"));
    assert(new SimpleGrantedAuthority("ROLE_A").toString() == "ROLE_A");
    assert(collectException!IllegalArgumentException(new SimpleGrantedAuthority("")) !is null);
    assert(AuthorityUtils.commaSeparatedStringToAuthorityList("A, B ,C").length == 3);
}

private UserDetailsSource users()
{
    return new UserDetailsSource;
}

private final class UserDetailsSource
{
    InMemoryUserDetailsManager manager;

    this()
    {
        manager = new InMemoryUserDetailsManager(new User("rod", "koala", roles("ROLE_ONE",
                "ROLE_TWO")), new User("peter", "opal", false, true, true, true, roles("ROLE_ONE")),
                new User("locked", "pw", true, true, true, false, roles("ROLE_ONE")));
    }
}

private DaoAuthenticationProvider daoProvider()
{
    auto provider = new DaoAuthenticationProvider(users().manager);
    provider.setPasswordEncoder(NoOpPasswordEncoder.getInstance());
    return provider;
}

private UsernamePasswordAuthenticationToken token(string name, string password)
{
    return UsernamePasswordAuthenticationToken.unauthenticated(Any.of(name), Any.of(password));
}

unittest
{
    // DaoAuthenticationProviderTests: testReceivedBadCredentialsWhenCredentialsNotProvided,
    // testAuthenticateFailsIfAccountLocked, testAuthenticateFailsIfUserDisabled, testAuthenticateFailsWithEmptyUsername,
    // testAuthenticateFailsWithInvalidPassword, testAuthenticateFailsWithInvalidUsernameAndHideUserNotFound...,
    // testAuthenticateFailsWithInvalidUsernameAndChangePasswordEncoder, testAuthenticates,
    // testAuthenticatesASecondTime, testGettersSetters, usernameNotFoundWhenNotHidden
    auto provider = daoProvider();
    assert(provider.supports(typeNameOf!UsernamePasswordAuthenticationToken) && !provider.supports("x.Other"));
    auto result = provider.authenticate(token("rod", "koala"));
    assert(result.isAuthenticated() && result.getName() == "rod" && result.getAuthorities().length == 2);
    assert(cast(UserDetails) result.getPrincipal().asObject() !is null);
    assert(provider.authenticate(token("rod", "koala")).isAuthenticated());
    assert(collectException!BadCredentialsException(provider.authenticate(token("rod", "wrong")))
            .msg == "Bad credentials");
    assert(collectException!BadCredentialsException(provider.authenticate(token("nobody", "x"))) !is null);
    assert(collectException!BadCredentialsException(provider.authenticate(token("rod", null))) !is null);
    assert(collectException!DisabledException(provider.authenticate(token("peter", "opal"))).msg == "User is disabled");
    assert(collectException!LockedException(provider.authenticate(token("locked", "pw")))
            .msg == "User account is locked");
    provider.setHideUserNotFoundExceptions(false);
    assert(collectException!UsernameNotFoundException(provider.authenticate(token("nobody", "x"))) !is null);
}

private final class NoDecision : AuthenticationProvider
{
    Authentication authenticate(Authentication)
    {
        return null;
    }

    bool supports(string)
    {
        return true;
    }
}

unittest
{
    // ProviderManagerTests: authenticationFailsWithUnsupportedToken, credentialsAreClearedByDefault,
    // authenticationSucceedsWithSupportedTokenAndReturnsExpectedObject, authenticationSucceedsWhenFirstProviderReturnsNull,
    // testStartupFailsIfProvidersNotSetAsList, parentAuthenticationIsUsedIfProvidersDontAuthenticate,
    // statusExceptionIsPublished (thrown, not published)
    assert(collectException!IllegalArgumentException(new ProviderManager(cast(AuthenticationProvider[]) null,
            null)) !is null);
    auto manager = new ProviderManager(new NoDecision, daoProvider());
    auto result = manager.authenticate(token("rod", "koala"));
    assert(result.isAuthenticated() && result.getCredentials().isNull);
    assert(collectException!BadCredentialsException(manager.authenticate(token("rod", "x"))) !is null);
    assert(collectException!DisabledException(manager.authenticate(token("peter", "opal"))) !is null);
    auto none = new ProviderManager([cast(AuthenticationProvider) new NoDecision], null);
    const e = collectException!ProviderNotFoundException(none.authenticate(token("rod", "koala")));
    assert(e !is null && e.msg == "No AuthenticationProvider found for "
            ~ typeNameOf!UsernamePasswordAuthenticationToken);
    auto child = new ProviderManager([cast(AuthenticationProvider) new NoDecision], manager);
    assert(child.authenticate(token("rod", "koala")).isAuthenticated());
}

unittest
{
    // AuthorityAuthorizationManagerTests: hasRoleWhenUserHasRoleThenGrantedDecision, hasRoleWhenUserHasNotRole...,
    // hasAnyRoleWhen..., hasAuthorityWhen..., hasRoleWhenContainRoleWithRolePrefixThenException,
    // hasAnyAuthorityWhen..., unauthenticated tokens denied
    Authentication rod = UsernamePasswordAuthenticationToken.authenticated(Any.of("rod"), Any.init,
            roles("ROLE_ADMIN", "WRITE"));
    Authentication unauthenticated = token("rod", "x");
    alias Manager = AuthorityAuthorizationManager!Object;
    assert(Manager.hasRole("ADMIN").authorize(() => rod, null).isGranted());
    assert(!Manager.hasRole("USER").authorize(() => rod, null).isGranted());
    assert(Manager.hasAnyRole("USER", "ADMIN").authorize(() => rod, null).isGranted());
    assert(Manager.hasAuthority("WRITE").authorize(() => rod, null).isGranted());
    assert(!Manager.hasAnyAuthority("READ").authorize(() => rod, null).isGranted());
    assert(!Manager.hasRole("ADMIN").authorize(() => unauthenticated, null).isGranted());
    assert(collectException!IllegalArgumentException(Manager.hasRole("ROLE_ADMIN")) !is null);
    assert(collectException!AuthorizationDeniedException(Manager.hasRole("USER").verify(() => rod,
            null)).msg == "Access Denied");
}

unittest
{
    // InMemoryUserDetailsManagerTests: changePassword aside, createUser, updateUser, deleteUser, userExists,
    // loadUserByUsername case-insensitively, a copy is returned
    auto manager = users().manager;
    assert(manager.userExists("ROD") && manager.loadUserByUsername("Rod").getUsername() == "rod");
    assert(collectException!IllegalArgumentException(manager.createUser(new User("rod", "x", null))) !is null);
    manager.updateUser(new User("rod", "new", roles("ROLE_X")));
    assert(manager.loadUserByUsername("rod").getPassword() == "new");
    manager.deleteUser("rod");
    assert(collectException!UsernameNotFoundException(manager.loadUserByUsername("rod")) !is null);
}

unittest
{
    // SecurityContextHolder off a fiber: thread-local, created on demand, cleared.
    SecurityContextHolder.clearContext();
    assert(SecurityContextHolder.getContext().getAuthentication() is null);
    auto rod = UsernamePasswordAuthenticationToken.authenticated(Any.of("rod"), Any.init, roles("ROLE_A"));
    SecurityContextHolder.setContext(new SecurityContextImpl(rod));
    assert(SecurityContextHolder.getContext().getAuthentication() is rod);
    assert(valueOf(cast(Object) SecurityContextHolder.getContext()) == "SecurityContextImpl [Authentication="
            ~ "UsernamePasswordAuthenticationToken [Principal=rod, Credentials=[PROTECTED], Authenticated=true, "
            ~ "Details=null, Granted Authorities=[ROLE_A]]]");
    SecurityContextHolder.clearContext();
    assert(SecurityContextHolder.getContext().getAuthentication() is null);
}

// ---- @PreAuthorize over a compiled expression

private final class Roles
{
    string OWNER_ADMIN = "ROLE_OWNER_ADMIN";
}

/// `hasRole(@roles.OWNER_ADMIN)` as Flint AOT compiles it.
private Any hasOwnerAdmin(imported!"flint.engine.aot.expression".EvaluationContext context)
{
    Any[] arguments = [Any.of((cast(Roles) context.bean("roles")).OWNER_ADMIN)];
    return context.rootFunction("hasRole", arguments);
}

unittest
{
    import flint.beans.factory.support : DefaultListableBeanFactory;
    import flint.engine.aot.descriptor : MergedAnnotation, MethodDescriptor;
    import flint.engine.aot.expression : ExpressionSpec;
    import flint.engine.aot.proxy : Invocation;
    import flint.security.access.prepost : PreAuthorize;
    import flint.security.authentication : AuthenticationCredentialsNotFoundException;
    import flint.security.authorization.method : PreAuthorizeMethodInterceptor;

    auto factory = new DefaultListableBeanFactory;
    factory.registerSingleton("roles", new Roles);
    auto interceptor = new PreAuthorizeMethodInterceptor(factory);
    auto method = new MethodDescriptor;
    method.name = "getOwner";
    method.annotations = [
        MergedAnnotation(typeNameOf!PreAuthorize, Any.of(PreAuthorize("hasRole(@roles.OWNER_ADMIN)")), 0)
    ];
    method.expressions = [
        ExpressionSpec(typeNameOf!PreAuthorize, "value", "hasRole(@roles.OWNER_ADMIN)", &hasOwnerAdmin)
    ];
    assert(interceptor.appliesTo(null, method) && interceptor.getOrder() == 200);
    Invocation invocation;
    invocation.method = method;
    bool called;
    void proceed(ref Invocation) @safe
    {
        called = true;
    }

    SecurityContextHolder.clearContext();
    assert(collectException!AuthenticationCredentialsNotFoundException(interceptor.invoke(invocation,
            &proceed)).msg == "An Authentication object was not found in the SecurityContext");
    auto vet = UsernamePasswordAuthenticationToken.authenticated(Any.of("vet"), Any.init, roles("ROLE_VET_ADMIN"));
    SecurityContextHolder.setContext(new SecurityContextImpl(vet));
    assert(collectException!AuthorizationDeniedException(interceptor.invoke(invocation, &proceed)) !is null && !called);
    auto admin = UsernamePasswordAuthenticationToken.authenticated(Any.of("admin"), Any.init,
            roles("ROLE_OWNER_ADMIN", "ROLE_VET_ADMIN"));
    SecurityContextHolder.setContext(new SecurityContextImpl(admin));
    interceptor.invoke(invocation, &proceed);
    assert(called);
    SecurityContextHolder.clearContext();
}
