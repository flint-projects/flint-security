// Ported from spring-security 7.2.0: crypto/src/test/java/org/springframework/security/crypto/password/DelegatingPasswordEncoderTests.java
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
 * crypto/src/test/java/org/springframework/security/crypto/password/DelegatingPasswordEncoderTests.java and
 * crypto/src/test/java/org/springframework/security/crypto/bcrypt/BCryptPasswordEncoderTests.java.
 */

/++
DelegatingPasswordEncoderTests (27 of 31): Mockito mocks become recording fakes. Not ported:
matchesWhenNullIdThenDelegatesToInvalidId (a D associative array has no null key), and the three
AbstractPasswordEncoderValidationTests cases that pass a CharSequence other than a String.
BCryptPasswordEncoderTests: the strength and format checks; hashing needs the pinned provider (decisions.md).
+/
module flint.security.crypto.password_encoder_test;

import flint.java.lang : IllegalArgumentException, UnsupportedOperationException;
import flint.engine.security.bcrypt : bcryptAvailable;
import flint.security.crypto.bcrypt : BCryptBackend, BCrypt, BCryptPasswordEncoder;
import flint.security.crypto.password : DelegatingPasswordEncoder, NoOpPasswordEncoder, PasswordEncoder;
import std.exception : collectException;

@safe:

private enum NO_PASSWORD_ENCODER_MAPPED = "There is no password encoder mapped for the id 'unmapped'. "
    ~ "Check your configuration to ensure it matches one of the registered encoders.";
private enum NO_PASSWORD_ENCODER_PREFIX = "Given that there is no default password encoder configured, each "
    ~ "password must have a password encoding prefix. Please either prefix this password with '{noop}' or set a "
    ~ "default password encoder in `DelegatingPasswordEncoder`.";
private enum MALFORMED_PASSWORD_ENCODER_PREFIX = "The name of the password encoder is improperly formatted or "
    ~ "incomplete. The format should be '{ENCODER}password'.";

/// A recording encoder (the mock of the Java tests).
private final class Fake : PasswordEncoder
{
    string[] calls;
    bool matchResult;
    bool upgradeResult;

    string encode(string raw)
    {
        calls ~= "encode " ~ raw;
        return "ENCODED-PASSWORD";
    }

    bool matches(string raw, string encoded)
    {
        calls ~= "matches " ~ raw ~ " " ~ encoded;
        return matchResult;
    }

    bool upgradeEncoding(string encoded)
    {
        calls ~= "upgrade " ~ encoded;
        return upgradeResult;
    }
}

private struct Fixture
{
    Fake bcrypt, noop;
    PasswordEncoder[string] delegates;
    DelegatingPasswordEncoder encoder;
}

private Fixture fixture()
{
    Fixture f;
    f.bcrypt = new Fake;
    f.noop = new Fake;
    f.delegates = ["bcrypt": cast(PasswordEncoder) f.bcrypt, "noop": f.noop];
    f.encoder = new DelegatingPasswordEncoder("bcrypt", f.delegates);
    return f;
}

private string thrown(T = IllegalArgumentException)(lazy bool action)
{
    try
        cast(void) action;
    catch (T e)
        return e.msg;
    return "<nothing thrown>";
}

unittest
{
    // constructorWhenIdForEncodeNullThenIllegalArgumentException ... constructorWhenPrefixContainsSuffix...
    auto f = fixture();
    assert(collectException!IllegalArgumentException(new DelegatingPasswordEncoder(null, f.delegates)) !is null);
    assert(collectException!IllegalArgumentException(new DelegatingPasswordEncoder("missing", f.delegates)) !is null);
    assert(collectException!IllegalArgumentException(new DelegatingPasswordEncoder("bcrypt",
            f.delegates, null, "}")) !is null);
    assert(collectException!IllegalArgumentException(new DelegatingPasswordEncoder("bcrypt",
            f.delegates, "{", null)) !is null);
    assert(collectException(new DelegatingPasswordEncoder("bcrypt", f.delegates, "", "}")) is null);
    assert(collectException!IllegalArgumentException(new DelegatingPasswordEncoder("bcrypt",
            f.delegates, "{", "")) !is null);
    assert(collectException!IllegalArgumentException(new DelegatingPasswordEncoder("bcrypt",
            f.delegates, "", "")) !is null);
    PasswordEncoder[string] badPrefix = ["{bcrypt": f.bcrypt];
    assert(collectException!IllegalArgumentException(new DelegatingPasswordEncoder("{bcrypt", badPrefix)) !is null);
    PasswordEncoder[string] badSuffix = ["bcrypt}": f.bcrypt];
    assert(collectException!IllegalArgumentException(new DelegatingPasswordEncoder("bcrypt}", badSuffix)) !is null);
    assert(collectException!IllegalArgumentException(new DelegatingPasswordEncoder("bcrypt",
            f.delegates, "}{", "}")) !is null);
    assert(collectException!IllegalArgumentException(f.encoder.setDefaultPasswordEncoderForMatches(null)) !is null);
}

unittest
{
    // matchesWhenCustomDefaultPasswordEncoderForMatchesThenDelegates, encodeWhenValidThenUsesIdForEncode
    auto f = fixture();
    auto fallback = new Fake;
    fallback.matchResult = true;
    f.encoder.setDefaultPasswordEncoderForMatches(fallback);
    assert(f.encoder.matches("password", "ENCODED-PASSWORD"));
    assert(fallback.calls == ["matches password ENCODED-PASSWORD"] && f.bcrypt.calls.length == 0);
    assert(fixture().encoder.encode("password") == "{bcrypt}ENCODED-PASSWORD");
}

unittest
{
    // matchesWhenBCryptThenDelegatesToBCrypt, matchesWhenNoopThenDelegatesToNoop
    auto f = fixture();
    f.bcrypt.matchResult = true;
    assert(f.encoder.matches("password", "{bcrypt}ENCODED-PASSWORD"));
    assert(f.bcrypt.calls == ["matches password ENCODED-PASSWORD"] && f.noop.calls.length == 0);
    f.noop.matchResult = true;
    assert(f.encoder.matches("password", "{noop}ENCODED-PASSWORD"));
    assert(f.noop.calls == ["matches password ENCODED-PASSWORD"]);
}

unittest
{
    // matchesWhenUnMappedThenIllegalArgumentException, matchesWhenNoClosingPrefixString..., matchesWhenNoStarting...,
    // matchesWhenNoIdString..., matchesWhenPrefixInMiddle..., matchesWhenIdIsNull...,
    // matchesShouldThrowIllegalArgumentExceptionWhenNoPasswordEncoderIsMappedForTheId
    auto f = fixture();
    assert(thrown(f.encoder.matches("password", "{unmapped}password")) == NO_PASSWORD_ENCODER_MAPPED);
    assert(thrown(f.encoder.matches("password", "{bcryptpassword")) == MALFORMED_PASSWORD_ENCODER_PREFIX);
    assert(thrown(f.encoder.matches("password", "bcrypt}password")) == MALFORMED_PASSWORD_ENCODER_PREFIX);
    assert(thrown(f.encoder.matches("password", "{}password")) == MALFORMED_PASSWORD_ENCODER_PREFIX);
    enum middle = "invalid{bcrypt}ENCODED-PASSWORD";
    assert(thrown(f.encoder.matches("password", middle)) == MALFORMED_PASSWORD_ENCODER_PREFIX);
    assert(thrown(f.encoder.matches("password", "password")) == NO_PASSWORD_ENCODER_PREFIX);
    assert(thrown(f.encoder.matches("rawPassword", "prefixEncodedPassword")) == NO_PASSWORD_ENCODER_PREFIX);
    assert(f.bcrypt.calls.length == 0 && f.noop.calls.length == 0);
}

unittest
{
    // upgradeEncodingWhenEncodedPasswordNullThenFalse ... upgradeEncodingWhenDifferentIdThenTrue
    auto f = fixture();
    assert(!f.encoder.upgradeEncoding(null));
    assert(f.encoder.upgradeEncoding("ENCODED-PASSWORD"));
    assert(f.encoder.upgradeEncoding("{bcryptENCODED-PASSWORD"));
    assert(!f.encoder.upgradeEncoding("{bcrypt}ENCODED-PASSWORD") && f.bcrypt.calls == [
        "upgrade ENCODED-PASSWORD"
    ]);
    f.bcrypt.upgradeResult = true;
    assert(f.encoder.upgradeEncoding("{bcrypt}ENCODED-PASSWORD"));
    assert(f.encoder.upgradeEncoding("{noop}ENCODED-PASSWORD") && f.bcrypt.calls.length == 2);
}

unittest
{
    // AbstractPasswordEncoderValidationTests: null and empty never match, null encodes to null.
    auto f = fixture();
    assert(f.encoder.encode(null) is null);
    assert(!f.encoder.matches(null, "{bcrypt}x") && !f.encoder.matches("", "{bcrypt}x"));
    assert(!f.encoder.matches("password", null) && !f.encoder.matches("password", ""));
    auto noop = NoOpPasswordEncoder.getInstance();
    assert(noop.encode("secret") == "secret" && noop.matches("secret", "secret") && !noop.matches("secret", "x"));
}

private final class StubBCrypt : BCryptBackend
{
    string hash(string, string version_, int strength)
    {
        import flint.java.lang : valueOf;

        return version_ ~ "$" ~ (strength < 10
                ? "0" : "") ~ valueOf(strength) ~ "$" ~ "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0";
    }

    bool check(string password, string)
    {
        return password == "password";
    }
}

unittest
{
    // BCryptPasswordEncoderTests: bad strengths, non-BCrypt values, upgradeEncoding by strength; the backend.
    assert(collectException!IllegalArgumentException(new BCryptPasswordEncoder(3)) !is null);
    assert(collectException!IllegalArgumentException(new BCryptPasswordEncoder(32)) !is null);
    auto encoder = new BCryptPasswordEncoder;
    assert(!encoder.matches("password", "012345678901234567890123456789"));
    enum hashed = "$2a$10$ymaklWBnpBKlgdMgkjWVF.GMGyvH8aDuTK.glFOaKw712LHtRRymS";
    if (!bcryptAvailable())
        assert(collectException!UnsupportedOperationException(encoder.matches("password", hashed)) !is null);
    assert(!encoder.upgradeEncoding(hashed) && new BCryptPasswordEncoder(11).upgradeEncoding(hashed));
    assert(collectException!IllegalArgumentException(encoder.upgradeEncoding("not-bcrypt")) !is null);
    BCrypt.install(new StubBCrypt);
    scope (exit)
        BCrypt.install(null);
    assert(encoder.matches("password", hashed) && !encoder.matches("wrong", hashed));
    assert(encoder.matches("password", encoder.encode("password")));
}

// BCryptPasswordEncoderTests over the pinned crypt_blowfish provider; they run where it is linked.

private alias Version = BCryptPasswordEncoder.BCryptVersion;

unittest
{
    if (!bcryptAvailable())
        return;
    foreach (version_; [Version._2A, Version._2Y, Version._2B])
    {
        // $2yMatches, $2aMatches, $2bMatches; ...NotMatches; ...Unicode; ...CustomStrength
        auto encoder = new BCryptPasswordEncoder(version_, 4);
        const result = encoder.encode("password");
        assert(result != "password" && result[0 .. 3] == version_ && result[4 .. 6] == "04");
        assert(encoder.matches("password", result) && !encoder.matches("bogus", result));
        assert(!encoder.matches("", result)); // emptyRawPasswordDoesNotMatchPassword
        const unicode = encoder.encode("passw\u9292rd");
        assert(!encoder.matches("pass\u9292\u9292rd", unicode) && encoder.matches("passw\u9292rd", unicode));
    }
}

unittest
{
    if (!bcryptAvailable())
        return;
    // doesntMatchNullEncodedValue, doesntMatchEmptyEncodedValue, doesntMatchBogusEncodedValue
    auto encoder = new BCryptPasswordEncoder(4);
    assert(!encoder.matches("password", null) && !encoder.matches("password", ""));
    assert(!encoder.matches("password", "012345678901234567890123456789"));
    // upgradeFromLowerStrength
    auto weak = new BCryptPasswordEncoder(4);
    auto strong = new BCryptPasswordEncoder(5);
    const weakPassword = weak.encode("password");
    const strongPassword = strong.encode("password");
    assert(!weak.upgradeEncoding(strongPassword) && strong.upgradeEncoding(weakPassword));
    // upgradeFromNullOrEmpty, upgradeFromNonBCrypt, upgradeWhenNoRoundsThenTrue
    assert(!encoder.upgradeEncoding(null) && !encoder.upgradeEncoding(""));
    assert(collectException!IllegalArgumentException(encoder.upgradeEncoding("not-a-bcrypt-password")) !is null);
    assert(encoder.upgradeEncoding("$2a$00$9N8N35BVs5TLqGL3pspAte5OWWA2a2aZIs.EGp7At7txYakFERMue"));
    // checkWhenNoRoundsThenTrue: deviation, crypt_blowfish refuses cost 00, so neither password matches.
    assert(!encoder.matches("password", "$2a$00$9N8N35BVs5TLqGL3pspAte5OWWA2a2aZIs.EGp7At7txYakFERMue"));
    // petclinic-rest's seeded admin/admin.
    enum admin = "$2a$10$ymaklWBnpBKlgdMgkjWVF.GMGyvH8aDuTK.glFOaKw712LHtRRymS";
    assert(new BCryptPasswordEncoder().matches("admin", admin));
}

unittest
{
    if (!bcryptAvailable())
        return;
    // encodeWhenPasswordOverMaxLengthThenThrowIllegalArgumentException, matchesWhenPasswordOverMaxLengthThenAllowToMatch
    auto encoder = new BCryptPasswordEncoder(4);
    enum password72chars = "123456789012345678901234567890123456789012345678901234567890123456789012";
    encoder.encode(password72chars);
    assert(collectException!IllegalArgumentException(encoder.encode(password72chars ~ "3")) !is null);
    const encoded72 = encoder.encode(password72chars);
    assert(encoder.matches(password72chars, encoded72) && encoder.matches(password72chars ~ "3", encoded72));
    // passwordLargerThan72BytesShouldThrowIllegalArgumentException: 70 characters, 72 UTF-8 bytes.
    const password72Bytes = "\u00e9\u00e9" ~ password72chars[0 .. 68];
    assert(password72Bytes.length == 72);
    encoder.encode(password72Bytes);
    assert(collectException!IllegalArgumentException(encoder.encode(password72Bytes ~ "a")) !is null);
}
