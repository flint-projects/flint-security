// Ported from spring-security 7.2.0: crypto/src/main/java/org/springframework/security/crypto/bcrypt/BCryptPasswordEncoder.java
// Copyright 2004-present the original author or authors.
// Licensed under the Apache License, Version 2.0.
// Modified by the Flint authors.
/*
 * BCrypt.java itself is not ported: AGENTS.md forbids a new cryptographic implementation. The hashing comes from a
 * BCryptBackend that a pinned native provider registers (decisions.md, "Open for the owner"); without one, encoding
 * and matching throw UnsupportedOperationException. The encoded-format check and upgradeEncoding are Spring's.
 */

/++
`org.springframework.security.crypto.bcrypt`: the BCrypt password encoder over a registered backend.
+/
module flint.security.crypto.bcrypt;

import flint.conc.slot : ProcessSlot;
import flint.java.lang : IllegalArgumentException, UnsupportedOperationException;
import flint.security.crypto.password : AbstractValidatingPasswordEncoder;

@safe:

/// The BCrypt hash function, provided by a pinned native library.
interface BCryptBackend
{
    /// `password` hashed with a fresh salt in `version` (`$2a`, `$2y`, `$2b`) at `strength` log rounds.
    string hash(string password, string version_, int strength);
    /// Whether `password` hashes to `hashed`.
    bool check(string password, string hashed);
}

private shared ProcessSlot!BCryptBackend backendSlot;

/// The registry of the BCrypt backend (Flint's replacement for the bundled `BCrypt.java`).
struct BCrypt
{
    /// The least and most log rounds.
    enum MIN_LOG_ROUNDS = 4, MAX_LOG_ROUNDS = 31;

    /// Register the backend, replacing any earlier one.
    static void install(BCryptBackend backend) nothrow @nogc
    {
        backendSlot.set(backend);
    }

    /// The backend. Throws `UnsupportedOperationException` when none is registered.
    static BCryptBackend backend()
    {
        auto found = backendSlot.get();
        if (found is null)
            throw new UnsupportedOperationException("BCrypt needs a pinned native provider; none is registered");
        return found;
    }
}

/// Spring Security's `BCryptPasswordEncoder`.
class BCryptPasswordEncoder : AbstractValidatingPasswordEncoder
{
    /// The hash versions.
    enum BCryptVersion : string
    {
        _2A = "$2a", /// Java's `$2A` (D identifiers cannot hold `$`)
        _2Y = "$2y", ///
        _2B = "$2b", ///
    }

    private BCryptVersion version_;
    private int strength;

    /// Strength 10, version `$2a`.
    this()
    {
        this(BCryptVersion._2A, -1);
    }

    /// `strength` log rounds (-1 for 10).
    this(int strength)
    {
        this(BCryptVersion._2A, strength);
    }

    /// `version_` at `strength` log rounds (-1 for 10).
    this(BCryptVersion version_, int strength = -1)
    {
        if (strength != -1 && (strength < BCrypt.MIN_LOG_ROUNDS || strength > BCrypt.MAX_LOG_ROUNDS))
            throw new IllegalArgumentException("Bad strength");
        this.version_ = version_;
        this.strength = strength == -1 ? 10 : strength;
    }

    protected override string encodeNonNullPassword(string rawPassword)
    {
        return BCrypt.backend().hash(rawPassword, version_, strength);
    }

    /// False when the value does not look like BCrypt, else the backend's check.
    protected override bool matchesNonNull(string rawPassword, string encodedPassword)
    {
        if (bcryptRounds(encodedPassword) < 0)
            return false;
        return BCrypt.backend().check(rawPassword, encodedPassword);
    }

    /// Whether the hash has fewer log rounds than this encoder's strength.
    protected override bool upgradeEncodingNonNull(string encodedPassword)
    {
        const rounds = bcryptRounds(encodedPassword);
        if (rounds < 0)
            throw new IllegalArgumentException("Encoded password does not look like BCrypt: " ~ encodedPassword);
        return rounds < strength;
    }

    /// The log rounds of a value matching Spring's `\A\$2(a|y|b)?\$(\d\d)\$[./0-9A-Za-z]{53}` (a prefix match),
    /// or -1 when it does not.
    private static int bcryptRounds(string encoded) pure nothrow @nogc
    {
        if (encoded.length < 3 || encoded[0 .. 2] != "$2")
            return -1;
        size_t i = 2;
        if (encoded[i] == 'a' || encoded[i] == 'y' || encoded[i] == 'b')
            i++;
        if (encoded.length < i + 4 + 53 || encoded[i] != '$' || encoded[i + 3] != '$')
            return -1;
        const tens = encoded[i + 1], ones = encoded[i + 2];
        if (!isDigit(tens) || !isDigit(ones) || !isBCryptText(encoded[i + 4 .. i + 4 + 53]))
            return -1;
        return (tens - '0') * 10 + (ones - '0');
    }

    private static bool isDigit(char c) pure nothrow @nogc
    {
        return c >= '0' && c <= '9';
    }

    private static bool isBCryptText(string text) pure nothrow @nogc
    {
        foreach (c; text)
            if (!(c == '.' || c == '/' || isDigit(c) || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')))
                return false;
        return true;
    }
}
