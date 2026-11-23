// Ported from spring-security 7.2.0: core/src/main/java/org/springframework/security/core/userdetails/jdbc/JdbcDaoImpl.java
// Copyright 2004-present the original author or authors.
// Licensed under the Apache License, Version 2.0.
// Modified by the Flint authors.
/*
 * Group authorities, setRolePrefix's message source and the JdbcDaoSupport base are reduced to the JdbcTemplate this
 * class needs; queries, defaults and the not-found messages are Spring's.
 */

/++
`org.springframework.security.core.userdetails.jdbc`: users and authorities from a database.
+/
module flint.security.core.userdetails.jdbc;

import flint.engine.aot.any : Any;
import flint.java.sql : ResultSet;
import flint.javax.sql : DataSource;
import flint.jdbc.core : JdbcTemplate, RowCallbackHandler;
import flint.security.core : GrantedAuthority, SimpleGrantedAuthority;
import flint.security.core.userdetails : User, UserDetails, UserDetailsService, UsernameNotFoundException;

@safe:

/// A `UserDetailsService` over JDBC (Spring Security's `JdbcDaoImpl`).
class JdbcDaoImpl : UserDetailsService
{
    /// The default users query: user name, password, enabled.
    enum DEF_USERS_BY_USERNAME_QUERY = "select username,password,enabled from users where username = ?";
    /// The default authorities query: user name, authority.
    enum DEF_AUTHORITIES_BY_USERNAME_QUERY = "select username,authority from authorities where username = ?";

    private JdbcTemplate jdbcTemplate;
    private string usersByUsernameQuery = DEF_USERS_BY_USERNAME_QUERY;
    private string authoritiesByUsernameQuery = DEF_AUTHORITIES_BY_USERNAME_QUERY;
    private string rolePrefix = "";
    private bool usernameBasedPrimaryKey = true;
    private bool enableAuthorities = true;

    /// Use `dataSource`.
    void setDataSource(DataSource dataSource)
    {
        jdbcTemplate = new JdbcTemplate(dataSource);
    }

    /// Use `jdbcTemplate`.
    void setJdbcTemplate(JdbcTemplate jdbcTemplate) pure nothrow @nogc
    {
        this.jdbcTemplate = jdbcTemplate;
    }

    /// The template.
    protected JdbcTemplate getJdbcTemplate() pure nothrow @nogc
    {
        return jdbcTemplate;
    }

    /// The users query: one parameter, the user name; columns user name, password, enabled.
    void setUsersByUsernameQuery(string query) pure nothrow @nogc
    {
        usersByUsernameQuery = query;
    }

    /// The authorities query: one parameter, the user name; columns user name, authority.
    void setAuthoritiesByUsernameQuery(string query) pure nothrow @nogc
    {
        authoritiesByUsernameQuery = query;
    }

    /// A prefix added to every authority read (`ROLE_`).
    void setRolePrefix(string rolePrefix) pure nothrow @nogc
    {
        this.rolePrefix = rolePrefix;
    }

    /// Whether the returned user keeps the name as given (true) or as stored (false).
    void setUsernameBasedPrimaryKey(bool usernameBasedPrimaryKey) pure nothrow @nogc
    {
        this.usernameBasedPrimaryKey = usernameBasedPrimaryKey;
    }

    /// Whether to load authorities.
    void setEnableAuthorities(bool enableAuthorities) pure nothrow @nogc
    {
        this.enableAuthorities = enableAuthorities;
    }

    /// The user and authorities named `username`. Throws `UsernameNotFoundException` for an unknown user or one
    /// without authorities.
    UserDetails loadUserByUsername(string username)
    {
        auto users = loadUsersByUsername(username);
        if (users.length == 0)
            throw new UsernameNotFoundException("User " ~ username ~ " not found");
        auto user = users[0];
        GrantedAuthority[] authorities;
        if (enableAuthorities)
            authorities = loadUserAuthorities(user.getUsername());
        if (authorities.length == 0)
            throw new UsernameNotFoundException("User " ~ username ~ " has no GrantedAuthority");
        return createUserDetails(username, user, authorities);
    }

    /// The users with name `username`, without authorities.
    protected UserDetails[] loadUsersByUsername(string username)
    {
        auto collector = new UserCollector;
        jdbcTemplate.query(usersByUsernameQuery, collector, [Any.of(username)]);
        return collector.users;
    }

    /// The authorities of `username`, with the role prefix.
    protected GrantedAuthority[] loadUserAuthorities(string username)
    {
        auto collector = new AuthorityCollector(rolePrefix);
        jdbcTemplate.query(authoritiesByUsernameQuery, collector, [Any.of(username)]);
        return collector.authorities;
    }

    /// The final user: the name as given or as stored, with the loaded authorities.
    protected UserDetails createUserDetails(string username, UserDetails userFromUserQuery,
            GrantedAuthority[] combinedAuthorities)
    {
        const name = usernameBasedPrimaryKey ? username : userFromUserQuery.getUsername();
        return new User(name, userFromUserQuery.getPassword(), userFromUserQuery.isEnabled(),
                userFromUserQuery.isAccountNonExpired(),
                userFromUserQuery.isCredentialsNonExpired(),
                userFromUserQuery.isAccountNonLocked(), combinedAuthorities);
    }

    private static final class UserCollector : RowCallbackHandler
    {
        UserDetails[] users;

        void processRow(ResultSet rs)
        {
            users ~= new User(rs.getString(1), rs.getString(2), rs.getBoolean(3), true, true, true, null);
        }
    }

    private static final class AuthorityCollector : RowCallbackHandler
    {
        GrantedAuthority[] authorities;
        private string prefix;

        this(string prefix)
        {
            this.prefix = prefix;
        }

        void processRow(ResultSet rs)
        {
            authorities ~= new SimpleGrantedAuthority(prefix ~ rs.getString(2));
        }
    }
}
