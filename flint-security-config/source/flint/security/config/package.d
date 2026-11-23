// Ported from spring-security 7.2.0: config/src/main/java/org/springframework/security/config/Customizer.java
// Copyright 2004-present the original author or authors.
// Licensed under the Apache License, Version 2.0.
// Modified by the Flint authors.

/++
`org.springframework.security.config`: the customizer callbacks of the configuration DSL.
+/
module flint.security.config;

@safe:

/// A callback that customizes a configurer (Spring Security's `Customizer`).
interface Customizer(T)
{
    /// Customize `t`.
    void customize(T t);

    /// A customizer that keeps the defaults (`Customizer.withDefaults()`).
    static Customizer!T withDefaults()
    {
        return new DelegateCustomizer!T(null);
    }

    /// A customizer running `action` (a Java lambda).
    static Customizer!T of(void delegate(T) @safe action)
    {
        return new DelegateCustomizer!T(action);
    }
}

private final class DelegateCustomizer(T) : Customizer!T
{
    private void delegate(T) @safe action;

    this(void delegate(T) @safe action)
    {
        this.action = action;
    }

    void customize(T t)
    {
        if (action !is null)
            action(t);
    }
}
