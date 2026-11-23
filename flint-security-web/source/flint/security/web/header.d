// Ported from spring-security 7.2.0: web/src/main/java/org/springframework/security/web/header
// Copyright 2004-present the original author or authors.
// Licensed under the Apache License, Version 2.0.
// Modified by the Flint authors.
/*
 * Ported from spring-security 7.2.0, web/src/main/java/org/springframework/security/web/header/{HeaderWriter,
 * HeaderWriterFilter}.java and header/writers/{XContentTypeOptionsHeaderWriter,XXssProtectionHeaderWriter,
 * CacheControlHeadersWriter,HstsHeaderWriter,StaticHeadersWriter}.java and writers/frameoptions/
 * XFrameOptionsHeaderWriter.java. HeaderWriterFilter writes the headers before the rest of the chain (Spring's
 * shouldWriteHeadersEagerly), since the servlet port has no response wrapper yet; the response is the same unless
 * the application sets Cache-Control, Expires or Pragma itself.
 */

/++
`org.springframework.security.web.header`: the security response headers.
+/
module flint.security.web.header;

import flint.jakarta.servlet : FilterChain;
import flint.jakarta.servlet.http : HttpServletRequest, HttpServletResponse;
import flint.security.web : SecurityFilter;

@safe:

/// Writes headers to a response (Spring Security's `HeaderWriter`).
interface HeaderWriter
{
    /// Write the headers.
    void writeHeaders(HttpServletRequest request, HttpServletResponse response);
}

/// Spring Security's `HeaderWriterFilter`.
class HeaderWriterFilter : SecurityFilter
{
    private HeaderWriter[] headerWriters;

    /// A filter applying `headerWriters` in order.
    this(HeaderWriter[] headerWriters...)
    {
        this.headerWriters = headerWriters.dup;
    }

    override void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
    {
        foreach (writer; headerWriters)
            writer.writeHeaders(request, response);
        chain.doFilter(request, response);
    }
}

/// `X-Content-Type-Options: nosniff`.
final class XContentTypeOptionsHeaderWriter : HeaderWriter
{
    /// Write it unless present.
    void writeHeaders(HttpServletRequest, HttpServletResponse response)
    {
        if (!response.containsHeader("X-Content-Type-Options"))
            response.setHeader("X-Content-Type-Options", "nosniff");
    }
}

/// `X-XSS-Protection`: `0` by default (Spring Security 6's `HeaderValue.DISABLED`).
final class XXssProtectionHeaderWriter : HeaderWriter
{
    /// The header values.
    enum HeaderValue : string
    {
        DISABLED = "0", ///
        ENABLED = "1", ///
        ENABLED_MODE_BLOCK = "1; mode=block", ///
    }

    private HeaderValue headerValue = HeaderValue.DISABLED;

    /// Set the value.
    void setHeaderValue(HeaderValue headerValue) pure nothrow @nogc
    {
        this.headerValue = headerValue;
    }

    /// Write it unless present.
    void writeHeaders(HttpServletRequest, HttpServletResponse response)
    {
        if (!response.containsHeader("X-XSS-Protection"))
            response.setHeader("X-XSS-Protection", headerValue);
    }
}

/// `Cache-Control: no-cache, no-store, max-age=0, must-revalidate`, `Pragma: no-cache`, `Expires: 0`, unless the
/// response already sets one of them (Spring Security's `CacheControlHeadersWriter`).
final class CacheControlHeadersWriter : HeaderWriter
{
    /// Write them unless any is present.
    void writeHeaders(HttpServletRequest, HttpServletResponse response)
    {
        if (response.getHeader("Cache-Control") !is null || response.getHeader("Expires") !is null
                || response.getHeader("Pragma") !is null)
            return;
        response.setHeader("Cache-Control", "no-cache, no-store, max-age=0, must-revalidate");
        response.setHeader("Pragma", "no-cache");
        response.setHeader("Expires", "0");
    }
}

/// `Strict-Transport-Security` on secure requests (Spring Security's `HstsHeaderWriter`).
final class HstsHeaderWriter : HeaderWriter
{
    private long maxAgeInSeconds = 31_536_000;
    private bool includeSubDomains = true;
    private bool preload;

    /// The max age.
    void setMaxAgeInSeconds(long maxAgeInSeconds) pure nothrow @nogc
    {
        this.maxAgeInSeconds = maxAgeInSeconds;
    }

    /// Whether to include subdomains.
    void setIncludeSubDomains(bool includeSubDomains) pure nothrow @nogc
    {
        this.includeSubDomains = includeSubDomains;
    }

    /// Write it on secure requests, unless present.
    void writeHeaders(HttpServletRequest request, HttpServletResponse response)
    {
        import flint.java.lang : valueOf;

        if (!request.isSecure() || response.containsHeader("Strict-Transport-Security"))
            return;
        response.setHeader("Strict-Transport-Security", "max-age=" ~ valueOf(maxAgeInSeconds) ~ (includeSubDomains
                ? " ; includeSubDomains" : "") ~ (preload ? " ; preload" : ""));
    }
}

/// `X-Frame-Options` (Spring Security's `XFrameOptionsHeaderWriter`).
final class XFrameOptionsHeaderWriter : HeaderWriter
{
    /// The policies.
    enum XFrameOptionsMode : string
    {
        DENY = "DENY", ///
        SAMEORIGIN = "SAMEORIGIN", ///
    }

    private XFrameOptionsMode mode;

    /// A writer for `mode` (`DENY` by default).
    this(XFrameOptionsMode mode = XFrameOptionsMode.DENY) pure nothrow @nogc
    {
        this.mode = mode;
    }

    /// Write it unless present.
    void writeHeaders(HttpServletRequest, HttpServletResponse response)
    {
        if (!response.containsHeader("X-Frame-Options"))
            response.setHeader("X-Frame-Options", mode);
    }
}

/// Fixed headers (Spring Security's `StaticHeadersWriter`).
final class StaticHeadersWriter : HeaderWriter
{
    private string name;
    private string[] values;

    /// A writer of `name: values`.
    this(string name, string[] values...)
    {
        this.name = name;
        this.values = values.dup;
    }

    /// Add each value unless the header is present.
    void writeHeaders(HttpServletRequest, HttpServletResponse response)
    {
        if (response.containsHeader(name))
            return;
        foreach (value; values)
            response.addHeader(name, value);
    }
}
