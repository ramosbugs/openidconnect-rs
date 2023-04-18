# [OpenID Connect](https://openid.net/specs/openid-connect-core-1_0.html) Library for Rust

[![crates.io](https://img.shields.io/crates/v/openidconnect.svg)](https://crates.io/crates/openidconnect)
[![docs.rs](https://docs.rs/openidconnect/badge.svg)](https://docs.rs/openidconnect)
[![Build Status](https://github.com/ramosbugs/openidconnect-rs/actions/workflows/main.yml/badge.svg)](https://github.com/ramosbugs/openidconnect-rs/actions/workflows/main.yml)
[![codecov](https://codecov.io/gh/ramosbugs/openidconnect-rs/branch/main/graph/badge.svg)](https://codecov.io/gh/ramosbugs/openidconnect-rs)

This library provides extensible, strongly-typed interfaces for the OpenID
Connect protocol.

API documentation and examples are available on [docs.rs](https://docs.rs/openidconnect).

## Minimum Supported Rust Version (MSRV)

The MSRV for *3.0.y* releases of this crate is Rust **1.57**.

The MSRV for *2.x.y* releases of this crate is Rust 1.45.

Since the 3.0.0 release, this crate maintains a policy of supporting
Rust releases going back at least 6 months. Changes that break compatibility with Rust releases
older than 6 months will no longer be considered SemVer breaking changes and will not result in a
new major version number for this crate.

## Standards

* [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html)
  * This crate passes the
    [Relying Party Certification](https://rp.certification.openid.net:8080/list?profile=C)
    conformance tests for `response_type=code`
  * Supported features:
    * Relying Party flows: code, implicit, hybrid
    * Standard claims
    * UserInfo endpoint
    * RSA, HMAC, and ECDSA (P-256/P-384 curves) ID token verification
  * Unsupported features:
    * Aggregated and distributed claims
    * Passing request parameters as JWTs
    * Verification of the `azp` claim (see [discussion](https://bitbucket.org/openid/connect/issues/973/))
    * ECDSA-based ID token verification using the P-521 curve
    * JSON Web Encryption (JWE)
* [OpenID Connect Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html)
  * Supported features:
    * Provider Metadata
  * Unsupported features:
    * WebFinger
* [OpenID Connect Dynamic Client Registration](https://openid.net/specs/openid-connect-registration-1_0.html)
  * Supported features:
    * Client Metadata
    * Client Registration endpoint
  * Unsupported features:
    * Client Configuration endpoint
* [OAuth 2.0 Token Introspection](https://tools.ietf.org/html/rfc7662)
* [OAuth 2.0 Token Revocation](https://tools.ietf.org/html/rfc7009)

## Sponsorship

This project is sponsored by [Unflakable](https://unflakable.com), a service
for tracking and quarantining flaky tests.
