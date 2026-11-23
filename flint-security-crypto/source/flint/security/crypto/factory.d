// Ported from spring-security 7.2.0: crypto/src/main/java/org/springframework/security/crypto/factory/PasswordEncoderFactories.java
// Copyright 2004-present the original author or authors.
// Licensed under the Apache License, Version 2.0.
// Modified by the Flint authors.

/++
`org.springframework.security.crypto.factory`: the default delegating encoder. Only `bcrypt` and `noop` are
registered: the other encoders of Java's map are not ported (Argon2 would come from engine-security).
+/
module flint.security.crypto.factory;

import flint.security.crypto.bcrypt : BCryptPasswordEncoder;
import flint.security.crypto.password : DelegatingPasswordEncoder, NoOpPasswordEncoder, PasswordEncoder;

@safe:

/// Spring Security's `PasswordEncoderFactories`.
struct PasswordEncoderFactories
{
    /// A `DelegatingPasswordEncoder` encoding with `bcrypt` and matching `{bcrypt}` and `{noop}` passwords.
    static PasswordEncoder createDelegatingPasswordEncoder()
    {
        PasswordEncoder[string] encoders = [
            "bcrypt": new BCryptPasswordEncoder, "noop": NoOpPasswordEncoder.getInstance()
        ];
        return new DelegatingPasswordEncoder("bcrypt", encoders);
    }
}
