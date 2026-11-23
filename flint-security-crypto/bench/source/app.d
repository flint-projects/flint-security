/// spring-security-crypto: PasswordEncoderFactories' DelegatingPasswordEncoder matching a `{noop}` password.
module app;

import flint.security.crypto.factory : PasswordEncoderFactories;
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
    auto encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
    const matched = encoder.matches(args.length > 1 ? args[1] : "koala", "{noop}koala");
    const upgrade = encoder.upgradeEncoding("{noop}koala");
    emit((matched ? "match" : "mismatch") ~ (upgrade ? " upgrade" : " current"));
    return 0;
}
