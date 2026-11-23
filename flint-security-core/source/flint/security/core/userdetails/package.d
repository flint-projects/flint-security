// Ported from spring-security 7.2.0: core/src/main/java/org/springframework/security/core/userdetails
// Copyright 2004-present the original author or authors.
// Licensed under the Apache License, Version 2.0.
// Modified by the Flint authors.
/*
 * Ported from spring-security 7.2.0, core/src/main/java/org/springframework/security/core/userdetails/{UserDetails,
 * User,UserDetailsService,UsernameNotFoundException,UserDetailsChecker}.java. User's builder is UserBuilder with
 * Java's methods; withDefaultPasswordEncoder is not ported.
 */

/++
`org.springframework.security.core.userdetails`: user records for authentication.
+/
module flint.security.core.userdetails;

import flint.java.lang : IllegalArgumentException;
import flint.security.core : AuthenticationException, authoritiesText, CredentialsContainer,
    GrantedAuthority, SimpleGrantedAuthority;

@safe:

/// Core user information (Spring Security's `UserDetails`).
interface UserDetails
{
    /// The authorities granted to the user.
    GrantedAuthority[] getAuthorities();
    /// The (encoded) password.
    string getPassword();
    /// The user name.
    string getUsername();
    /// Whether the account has not expired (Java's default: true).
    bool isAccountNonExpired();
    /// Whether the account is not locked (Java's default: true).
    bool isAccountNonLocked();
    /// Whether the credentials have not expired (Java's default: true).
    bool isCredentialsNonExpired();
    /// Whether the user is enabled (Java's default: true).
    bool isEnabled();
}

/// Loads users by name (Spring Security's `UserDetailsService`).
interface UserDetailsService
{
    /// The user named `username`. Throws `UsernameNotFoundException` when there is none.
    UserDetails loadUserByUsername(string username);
}

/// Checks a loaded user's account status.
interface UserDetailsChecker
{
    /// Throw an `AuthenticationException` when `user` may not authenticate.
    void check(UserDetails user);
}

/// Thrown when a user cannot be found.
class UsernameNotFoundException : AuthenticationException
{
    /// A failure with `message`.
    this(string message, Throwable cause = null, string file = __FILE__, size_t line = __LINE__) pure nothrow
    {
        super(message, cause, file, line);
    }

    /// For the user named `username`.
    static UsernameNotFoundException fromUsername(string username)
    {
        return new UsernameNotFoundException("user '" ~ username ~ "' was not found");
    }
}

/// Spring Security's `User`: a `UserDetails` holding its fields.
class User : UserDetails, CredentialsContainer
{
    private string password;
    private string username;
    private GrantedAuthority[] authorities;
    private bool accountNonExpired, accountNonLocked, credentialsNonExpired, enabled;

    /// An enabled user with non-expired, unlocked account and credentials.
    this(string username, string password, GrantedAuthority[] authorities)
    {
        this(username, password, true, true, true, true, authorities);
    }

    /// A user with every flag. Throws `IllegalArgumentException` for an empty name.
    this(string username, string password, bool enabled, bool accountNonExpired,
            bool credentialsNonExpired, bool accountNonLocked, GrantedAuthority[] authorities)
    {
        if (username.length == 0)
            throw new IllegalArgumentException("Cannot pass null or empty values to constructor");
        foreach (authority; authorities)
            if (authority is null)
                throw new IllegalArgumentException("GrantedAuthority list cannot contain any null elements");
        this.username = username;
        this.password = password;
        this.enabled = enabled;
        this.accountNonExpired = accountNonExpired;
        this.credentialsNonExpired = credentialsNonExpired;
        this.accountNonLocked = accountNonLocked;
        this.authorities = sortAuthorities(authorities);
    }

    /// The authorities, sorted by their text.
    GrantedAuthority[] getAuthorities()
    {
        return authorities.dup;
    }

    /// The password, or null once erased.
    string getPassword()
    {
        return password;
    }

    /// The user name.
    string getUsername()
    {
        return username;
    }

    /// Whether enabled.
    bool isEnabled()
    {
        return enabled;
    }

    /// Whether the account has not expired.
    bool isAccountNonExpired()
    {
        return accountNonExpired;
    }

    /// Whether the account is not locked.
    bool isAccountNonLocked()
    {
        return accountNonLocked;
    }

    /// Whether the credentials have not expired.
    bool isCredentialsNonExpired()
    {
        return credentialsNonExpired;
    }

    /// Forget the password.
    void eraseCredentials()
    {
        password = null;
    }

    /// Equal user names.
    override bool opEquals(Object obj)
    {
        auto that = cast(User) obj;
        return that !is null && that.username == username;
    }

    /// The user name's hash.
    override size_t toHash() nothrow
    {
        return hashOf(username);
    }

    /// `flint.security.core.userdetails.User [Username=..., Password=[PROTECTED], ...]`.
    override string toString()
    {
        import flint.engine.aot.name : canonicalTypeName;
        import flint.java.lang : valueOf;

        return canonicalTypeName(typeid(this).name) ~ " [Username=" ~ username
            ~ ", Password=[PROTECTED], Enabled=" ~ valueOf(enabled) ~ ", AccountNonExpired=" ~ valueOf(
                    accountNonExpired) ~ ", CredentialsNonExpired=" ~ valueOf(
                    credentialsNonExpired) ~ ", AccountNonLocked=" ~ valueOf(
                    accountNonLocked) ~ ", Granted Authorities=" ~ authoritiesText(authorities) ~ "]";
    }

    /// A builder for a user named `username`.
    static UserBuilder withUsername(string username)
    {
        return new UserBuilder().username(username);
    }

    /// A builder starting from `user`.
    static UserBuilder withUserDetails(UserDetails user)
    {
        return withUsername(user.getUsername()).password(user.getPassword())
            .accountExpired(!user.isAccountNonExpired()).accountLocked(!user.isAccountNonLocked())
            .authorities(user.getAuthorities()).credentialsExpired(!user.isCredentialsNonExpired())
            .disabled(!user.isEnabled());
    }

    private static GrantedAuthority[] sortAuthorities(GrantedAuthority[] authorities)
    {
        GrantedAuthority[] sorted;
        foreach (authority; authorities)
        {
            bool present;
            foreach (existing; sorted)
                present |= existing.getAuthority() == authority.getAuthority();
            if (!present)
                sorted ~= authority;
        }
        foreach (i; 1 .. sorted.length)
            for (size_t j = i; j > 0 && sorted[j].getAuthority() < sorted[j - 1].getAuthority(); j--)
                sorted[j - 1 .. j + 1] = [sorted[j], sorted[j - 1]];
        return sorted;
    }
}

/// Builds a `User` (Spring Security's `User.UserBuilder`).
final class UserBuilder
{
    private string username_, password_;
    private GrantedAuthority[] authorities_;
    private bool accountExpired_, accountLocked_, credentialsExpired_, disabled_;

    /// The user name. Throws `IllegalArgumentException` for null.
    UserBuilder username(string username)
    {
        if (username is null)
            throw new IllegalArgumentException("username cannot be null");
        username_ = username;
        return this;
    }

    /// The (encoded) password.
    UserBuilder password(string password)
    {
        password_ = password;
        return this;
    }

    /// Roles, each granted as `ROLE_<role>`. Throws `IllegalArgumentException` for a role already prefixed.
    UserBuilder roles(string[] roles...)
    {
        GrantedAuthority[] result;
        foreach (role; roles)
        {
            if (role.length >= 5 && role[0 .. 5] == "ROLE_")
                throw new IllegalArgumentException(role ~ " cannot start with ROLE_ (it is automatically added)");
            result ~= new SimpleGrantedAuthority("ROLE_" ~ role);
        }
        return authorities(result);
    }

    /// The authorities.
    UserBuilder authorities(GrantedAuthority[] authorities...)
    {
        authorities_ = authorities.dup;
        return this;
    }

    /// The authorities named.
    UserBuilder authorities(string[] authorities...)
    {
        import flint.security.core : AuthorityUtils;

        return this.authorities(AuthorityUtils.createAuthorityList(authorities));
    }

    /// Whether the account has expired.
    UserBuilder accountExpired(bool accountExpired)
    {
        accountExpired_ = accountExpired;
        return this;
    }

    /// Whether the account is locked.
    UserBuilder accountLocked(bool accountLocked)
    {
        accountLocked_ = accountLocked;
        return this;
    }

    /// Whether the credentials have expired.
    UserBuilder credentialsExpired(bool credentialsExpired)
    {
        credentialsExpired_ = credentialsExpired;
        return this;
    }

    /// Whether the user is disabled.
    UserBuilder disabled(bool disabled)
    {
        disabled_ = disabled;
        return this;
    }

    /// The user.
    UserDetails build()
    {
        return new User(username_, password_, !disabled_, !accountExpired_,
                !credentialsExpired_, !accountLocked_, authorities_);
    }
}
