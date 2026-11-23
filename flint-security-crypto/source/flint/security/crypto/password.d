// Ported from spring-security 7.2.0: crypto/src/main/java/org/springframework/security/crypto/password
// Copyright 2004-present the original author or authors.
// Licensed under the Apache License, Version 2.0.
// Modified by the Flint authors.
/*
 * Ported from spring-security 7.2.0, crypto/src/main/java/org/springframework/security/crypto/password/
 * {PasswordEncoder,AbstractValidatingPasswordEncoder,DelegatingPasswordEncoder,NoOpPasswordEncoder}.java.
 * Java's CharSequence is string. The digest-based legacy encoders (LDAP SHA, MD4, MessageDigest, Standard,
 * Pbkdf2) are not ported.
 */

/++
`org.springframework.security.crypto.password`: one-way password encoding.
+/
module flint.security.crypto.password;

import flint.java.lang : IllegalArgumentException, UnsupportedOperationException;

@safe:

/// Encodes passwords (Spring Security's `PasswordEncoder`).
interface PasswordEncoder
{
    /// The encoded form of `rawPassword`; null for null.
    string encode(string rawPassword);
    /// Whether `rawPassword` encodes to `encodedPassword`.
    bool matches(string rawPassword, string encodedPassword);
    /// Whether `encodedPassword` should be encoded again for better security (Java's default: false).
    bool upgradeEncoding(string encodedPassword);
}

/// Validates the arguments before delegating to the subclass (Spring Security's
/// `AbstractValidatingPasswordEncoder`): null encodes to null, and null or empty never matches.
abstract class AbstractValidatingPasswordEncoder : PasswordEncoder
{
    /// `encodeNonNullPassword`, or null for null.
    final string encode(string rawPassword)
    {
        return rawPassword is null ? null : encodeNonNullPassword(rawPassword);
    }

    /// The encoding of a non-null password.
    protected abstract string encodeNonNullPassword(string rawPassword);

    /// False for a null or empty argument, else `matchesNonNull`.
    final bool matches(string rawPassword, string encodedPassword)
    {
        if (rawPassword.length == 0 || encodedPassword.length == 0)
            return false;
        return matchesNonNull(rawPassword, encodedPassword);
    }

    /// Whether two non-empty values match.
    protected abstract bool matchesNonNull(string rawPassword, string encodedPassword);

    /// False for a null or empty value, else `upgradeEncodingNonNull`.
    final bool upgradeEncoding(string encodedPassword)
    {
        return encodedPassword.length != 0 && upgradeEncodingNonNull(encodedPassword);
    }

    /// Whether a non-empty value needs upgrading (false by default).
    protected bool upgradeEncodingNonNull(string)
    {
        return false;
    }
}

/// Stores passwords as they are: for tests only (Spring Security's deprecated `NoOpPasswordEncoder`).
final class NoOpPasswordEncoder : AbstractValidatingPasswordEncoder
{
    private this() pure nothrow @nogc
    {
    }

    /// The shared instance.
    static PasswordEncoder getInstance()
    {
        return new NoOpPasswordEncoder;
    }

    protected override string encodeNonNullPassword(string rawPassword)
    {
        return rawPassword;
    }

    protected override bool matchesNonNull(string rawPassword, string encodedPassword)
    {
        return rawPassword == encodedPassword;
    }
}

/++
A password encoder that delegates by an id prefix: `{bcrypt}$2a$10$...`, `{noop}password` (Spring Security's
`DelegatingPasswordEncoder`). New passwords are encoded with `idForEncode`.
+/
class DelegatingPasswordEncoder : AbstractValidatingPasswordEncoder
{
    private enum NO_PASSWORD_ENCODER_PREFIX = "Given that there is no default password encoder configured, each "
        ~ "password must have a password encoding prefix. Please either prefix this password with '{noop}' or "
        ~ "set a default password encoder in `DelegatingPasswordEncoder`.";

    private string idPrefix;
    private string idSuffix;
    private string idForEncode;
    private PasswordEncoder passwordEncoderForEncode;
    private PasswordEncoder[string] idToPasswordEncoder;
    private PasswordEncoder defaultPasswordEncoderForMatches;

    /// Encode with `idForEncode` from `idToPasswordEncoder`, with `{` and `}` around ids.
    this(string idForEncode, PasswordEncoder[string] idToPasswordEncoder)
    {
        this(idForEncode, idToPasswordEncoder, "{", "}");
    }

    /// Encode with `idForEncode`, with `idPrefix` and `idSuffix` around ids.
    this(string idForEncode, PasswordEncoder[string] idToPasswordEncoder, string idPrefix, string idSuffix)
    {
        if (idForEncode is null)
            throw new IllegalArgumentException("idForEncode cannot be null");
        if (idPrefix is null)
            throw new IllegalArgumentException("prefix cannot be null");
        if (idSuffix.length == 0)
            throw new IllegalArgumentException("suffix cannot be empty");
        if (contains(idPrefix, idSuffix))
            throw new IllegalArgumentException("idPrefix " ~ idPrefix ~ " cannot contain idSuffix " ~ idSuffix);
        if ((idForEncode in idToPasswordEncoder) is null)
            throw new IllegalArgumentException("idForEncode " ~ idForEncode ~ "is not found in idToPasswordEncoder");
        foreach (id, encoder; idToPasswordEncoder)
        {
            if (idPrefix.length && contains(id, idPrefix))
                throw new IllegalArgumentException("id " ~ id ~ " cannot contain " ~ idPrefix);
            if (contains(id, idSuffix))
                throw new IllegalArgumentException("id " ~ id ~ " cannot contain " ~ idSuffix);
        }
        this.idForEncode = idForEncode;
        passwordEncoderForEncode = idToPasswordEncoder[idForEncode];
        this.idToPasswordEncoder = idToPasswordEncoder.dup;
        this.idPrefix = idPrefix;
        this.idSuffix = idSuffix;
        defaultPasswordEncoderForMatches = new UnmappedIdPasswordEncoder;
    }

    /// The encoder for passwords without a mapped id (by default, one that throws `IllegalArgumentException`).
    void setDefaultPasswordEncoderForMatches(PasswordEncoder encoder)
    {
        if (encoder is null)
            throw new IllegalArgumentException("defaultPasswordEncoderForMatches cannot be null");
        defaultPasswordEncoderForMatches = encoder;
    }

    protected override string encodeNonNullPassword(string rawPassword)
    {
        return idPrefix ~ idForEncode ~ idSuffix ~ passwordEncoderForEncode.encode(rawPassword);
    }

    protected override bool matchesNonNull(string rawPassword, string prefixEncodedPassword)
    {
        const id = extractId(prefixEncodedPassword);
        auto delegate_ = id is null ? null : idToPasswordEncoder.get(id, null);
        if (delegate_ is null)
            return defaultPasswordEncoderForMatches.matches(rawPassword, prefixEncodedPassword);
        return delegate_.matches(rawPassword, extractEncodedPassword(prefixEncodedPassword));
    }

    protected override bool upgradeEncodingNonNull(string prefixEncodedPassword)
    {
        const id = extractId(prefixEncodedPassword);
        if (id is null || !equalsIgnoreCase(idForEncode, id))
            return true;
        return passwordEncoderForEncode.upgradeEncoding(extractEncodedPassword(prefixEncodedPassword));
    }

    /// The id between the prefix and the suffix at the start of the value, or null.
    private string extractId(string prefixEncodedPassword) const
    {
        if (indexOf(prefixEncodedPassword, idPrefix, 0) != 0)
            return null;
        const end = indexOf(prefixEncodedPassword, idSuffix, 0);
        if (end < 0)
            return null;
        return prefixEncodedPassword[idPrefix.length .. end];
    }

    private string extractEncodedPassword(string prefixEncodedPassword) const
    {
        const start = indexOf(prefixEncodedPassword, idSuffix, 0);
        return prefixEncodedPassword[start + idSuffix.length .. $];
    }

    /// The default for unmapped ids: rejects with an explanation.
    private final class UnmappedIdPasswordEncoder : AbstractValidatingPasswordEncoder
    {
        protected override string encodeNonNullPassword(string)
        {
            throw new UnsupportedOperationException("encode is not supported");
        }

        protected override bool matchesNonNull(string, string prefixEncodedPassword)
        {
            const id = extractId(prefixEncodedPassword);
            if (id !is null && !isBlank(id))
                throw new IllegalArgumentException("There is no password encoder mapped for the id '" ~ id
                        ~ "'. Check your configuration to ensure it matches one of the registered encoders.");
            if (!isBlank(prefixEncodedPassword))
            {
                const start = indexOf(prefixEncodedPassword, idPrefix, 0);
                const end = indexOf(prefixEncodedPassword, idSuffix, start < 0 ? 0 : start);
                if (start < 0 && end < 0)
                    throw new IllegalArgumentException(NO_PASSWORD_ENCODER_PREFIX);
            }
            throw new IllegalArgumentException("The name of the password encoder is improperly formatted or "
                    ~ "incomplete. The format should be '" ~ idPrefix ~ "ENCODER" ~ idSuffix ~ "password'.");
        }
    }
}

package(flint.security) ptrdiff_t indexOf(string text, string part, size_t from) pure nothrow @nogc
{
    if (part.length == 0)
        return from <= text.length ? cast(ptrdiff_t) from : -1;
    foreach (i; from .. text.length >= part.length ? text.length - part.length + 1 : from)
        if (text[i .. i + part.length] == part)
            return i;
    return -1;
}

package(flint.security) bool contains(string text, string part) pure nothrow @nogc
{
    return indexOf(text, part, 0) >= 0;
}

private bool isBlank(string text) pure nothrow @nogc
{
    foreach (c; text)
        if (c != ' ' && c != '\t' && c != '\n' && c != '\r' && c != '\f' && c != '\v')
            return false;
    return true;
}

private bool equalsIgnoreCase(string a, string b) pure nothrow @nogc
{
    if (a.length != b.length)
        return false;
    foreach (i, c; a)
        if ((c | (c >= 'A' && c <= 'Z' ? 0x20 : 0)) != (b[i] | (b[i] >= 'A' && b[i] <= 'Z' ? 0x20 : 0)))
            return false;
    return true;
}
