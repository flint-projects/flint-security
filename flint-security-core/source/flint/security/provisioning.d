// Ported from spring-security 7.2.0: core/src/main/java/org/springframework/security/provisioning
// Copyright 2004-present the original author or authors.
// Licensed under the Apache License, Version 2.0.
// Modified by the Flint authors.
/*
 * Ported from spring-security 7.2.0, core/src/main/java/org/springframework/security/provisioning/{
 * UserDetailsManager,InMemoryUserDetailsManager}.java. changePassword needs the current authentication and is not
 * ported; JdbcUserDetailsManager is reduced to JdbcDaoImpl (flint.security.core.userdetails.jdbc).
 */

/++
`org.springframework.security.provisioning`: user stores that can be changed.
+/
module flint.security.provisioning;

import flint.java.lang : IllegalArgumentException;
import flint.security.core.userdetails : User, UserDetails, UserDetailsService, UsernameNotFoundException;

@safe:

/// A `UserDetailsService` that can create and change users (Spring Security's `UserDetailsManager`).
interface UserDetailsManager : UserDetailsService
{
    /// Add `user`.
    void createUser(UserDetails user);
    /// Replace `user`.
    void updateUser(UserDetails user);
    /// Remove the user named `username`.
    void deleteUser(string username);
    /// Whether the user named `username` exists.
    bool userExists(string username);
}

/// Users held in memory, by lower-cased name (Spring Security's `InMemoryUserDetailsManager`).
class InMemoryUserDetailsManager : UserDetailsManager
{
    private UserDetails[string] users;

    /// A manager holding `users`.
    this(UserDetails[] users...)
    {
        foreach (user; users)
            add(user);
    }

    private void add(UserDetails user)
    {
        if ((lower(user.getUsername()) in this.users) !is null)
            throw new IllegalArgumentException("user should not exist");
        this.users[lower(user.getUsername())] = user;
    }

    /// Add `user`. Throws `IllegalArgumentException` when the name exists.
    void createUser(UserDetails user)
    {
        if (userExists(user.getUsername()))
            throw new IllegalArgumentException("user should not exist");
        users[lower(user.getUsername())] = user;
    }

    /// Replace `user`. Throws `IllegalArgumentException` when the name does not exist.
    void updateUser(UserDetails user)
    {
        if (!userExists(user.getUsername()))
            throw new IllegalArgumentException("user should exist");
        users[lower(user.getUsername())] = user;
    }

    /// Remove the user named `username`.
    void deleteUser(string username)
    {
        users.remove(lower(username));
    }

    /// Whether the user exists.
    bool userExists(string username)
    {
        return (lower(username) in users) !is null;
    }

    /// A copy of the user named `username`. Throws `UsernameNotFoundException`.
    UserDetails loadUserByUsername(string username)
    {
        auto user = lower(username) in users;
        if (user is null)
            throw new UsernameNotFoundException(username);
        return new User(user.getUsername(), user.getPassword(), user.isEnabled(),
                user.isAccountNonExpired(), user.isCredentialsNonExpired(),
                user.isAccountNonLocked(), user.getAuthorities());
    }

    private static string lower(string text) pure nothrow
    {
        char[] result = text.dup;
        foreach (ref c; result)
            if (c >= 'A' && c <= 'Z')
                c += 32;
        return result.idup;
    }
}
