/// Control for the flint:security-config probe: the same program and output without the module (PROBE_CONTRACT.md).
module app;

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
    emit(args.length > 1 ? "permitAll 6" : "authenticated 6");
    return 0;
}
