// Ported from spring-security 7.2.0: core/src/main/java/org/springframework/security/authorization/method
// Copyright 2004-present the original author or authors.
// Licensed under the Apache License, Version 2.0.
// Modified by the Flint authors.
/*
 * Ported from spring-security 7.2.0, core/src/main/java/org/springframework/security/authorization/method/{
 * PreAuthorizeAuthorizationManager,AuthorizationManagerBeforeMethodInterceptor,AuthorizationInterceptorsOrder,
 * MethodSecurityExpressionRoot}.java. The interceptor is a Flint AOT Advisor on the proxy chain; the expression is
 * the one Flint AOT compiled for the method's @PreAuthorize (contract 3), evaluated over the invocation.
 */

/++
`org.springframework.security.authorization.method`: `@PreAuthorize` on the proxy chain.
+/
module flint.security.authorization.method;

import flint.beans.factory : BeanFactory;
import flint.engine.aot.any : Any;
import flint.engine.aot.descriptor : Descriptor, findAnnotation, MethodDescriptor;
import flint.engine.aot.expression : isTrue;
import flint.engine.aot.name : typeNameOf;
import flint.engine.aot.proxy : Advisor, Invocation, Proceed;
import flint.java.lang : IllegalStateException;
import flint.security.access.expression : SecurityExpressionRoot;
import flint.security.access.prepost : PreAuthorize;
import flint.security.authentication : AuthenticationCredentialsNotFoundException;
import flint.security.authorization : AuthorizationDecision, AuthorizationDeniedException;
import flint.security.core : Authentication;
import flint.security.core.context : SecurityContextHolder;

@safe:

/// The order of the method-security interceptors (Spring Security's `AuthorizationInterceptorsOrder`).
enum AuthorizationInterceptorsOrder : int
{
    FIRST = int.min, ///
    PRE_FILTER = 100, ///
    PRE_AUTHORIZE = 200, ///
    SECURED = 300, ///
    JSR250 = 400, ///
    SECURE_RESULT = 450, ///
    POST_AUTHORIZE = 500, ///
    POST_FILTER = 600, ///
    LAST = int.max, ///
}

/// The root of method-security expressions: the invocation's arguments and result (Spring Security's
/// `MethodSecurityExpressionRoot`, as a Flint AOT evaluation context).
class MethodSecurityExpressionRoot : SecurityExpressionRoot
{
    private Any[] arguments;
    private Any returnObject;
    private string name;
    private BeanFactory beanFactory;

    /// A root for a call of `methodName` with `arguments` (and `returnObject` after it), resolving `@name` beans in
    /// `beanFactory`. The arguments are copied: the root may outlive the invocation's frame.
    this(Authentication delegate() @safe authentication, string methodName, scope Any[] arguments,
            Any returnObject, BeanFactory beanFactory)
    {
        super(authentication);
        name = methodName;
        this.arguments = arguments.dup;
        this.returnObject = returnObject;
        this.beanFactory = beanFactory;
    }

    /// `#p0`, `#a0`, `#name`.
    Any argument(size_t index)
    {
        return index < arguments.length ? arguments[index] : Any.init;
    }

    /// `#result` / `returnObject`.
    Any result()
    {
        return returnObject;
    }

    /// `#root.methodName`.
    string methodName()
    {
        return name;
    }

    /// `@name`.
    Object bean(string name)
    {
        if (beanFactory is null)
            throw new IllegalStateException("No bean resolver for @" ~ name);
        return beanFactory.getBean(name);
    }

    /// `${...}`: the text as is (method-security expressions resolve no placeholders).
    string placeholder(string text)
    {
        return text;
    }
}

/++
Spring Security's `AuthorizationManagerBeforeMethodInterceptor` for `@PreAuthorize`: before the call, evaluates the
compiled expression with the current authentication, and throws `AuthorizationDeniedException` unless it holds.
+/
class PreAuthorizeMethodInterceptor : Advisor
{
    private BeanFactory beanFactory;
    private int order = AuthorizationInterceptorsOrder.PRE_AUTHORIZE;

    /// An interceptor resolving `@name` beans in `beanFactory`.
    this(BeanFactory beanFactory)
    {
        this.beanFactory = beanFactory;
    }

    /// Methods annotated `@PreAuthorize` (on the method or its class).
    bool appliesTo(const Descriptor, const(MethodDescriptor)* method)
    {
        return findAnnotation(method.annotations, typeNameOf!PreAuthorize) !is null;
    }

    /// The order (`PRE_AUTHORIZE`).
    int getOrder()
    {
        return order;
    }

    /// Set the order.
    void setOrder(int order) pure nothrow @nogc
    {
        this.order = order;
    }

    /// Authorize, then proceed. Throws `AuthenticationCredentialsNotFoundException` without an authentication,
    /// `AuthorizationDeniedException` when the expression is false.
    void invoke(ref Invocation invocation, scope Proceed proceed)
    {
        auto spec = invocation.method.expression(typeNameOf!PreAuthorize, "value");
        if (spec is null || spec.evaluate is null)
            throw new IllegalStateException("@PreAuthorize on " ~ invocation.method.name
                    ~ " was not compiled (generated before AOT contract 3); rebuild with flint build");
        auto root = new MethodSecurityExpressionRoot(&currentAuthentication,
                invocation.method.name, invocation.arguments, invocation.result, beanFactory);
        if (!isTrue(spec.evaluate(root)))
            throw new AuthorizationDeniedException("Access Denied", new AuthorizationDecision(false));
        proceed(invocation);
    }

    private Authentication currentAuthentication()
    {
        auto authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication is null)
            throw new AuthenticationCredentialsNotFoundException(
                    "An Authentication object was not found in the SecurityContext");
        return authentication;
    }
}
