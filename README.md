# [OpenID Connect](https://openid.net/specs/openid-connect-core-1_0.html) Library for Rust

[![crates.io](https://img.shields.io/crates/v/openidconnect.svg)](https://crates.io/crates/openidconnect)
[![docs.rs](https://docs.rs/openidconnect/badge.svg)](https://docs.rs/openidconnect)
[![Build Status](https://travis-ci.org/ramosbugs/openidconnect-rs.svg?branch=main)](https://travis-ci.org/ramosbugs/openidconnect-rs)
[![codecov](https://codecov.io/gh/ramosbugs/openidconnect-rs/branch/main/graph/badge.svg)](https://codecov.io/gh/ramosbugs/openidconnect-rs)


This library provides extensible, strongly-typed interfaces for the OpenID Connect protocol.

API documentation and examples are available on [docs.rs](https://docs.rs/openidconnect).

# Standards

* [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html)
  * This crate passes the
    [Relying Party Certification](https://rp.certification.openid.net:8080/list?profile=C)
    conformance tests for `response_type=code`
  * Supported features:
    * Relying Party flows: code, implicit, hybrid
    * Standard claims
    * UserInfo endpoint
    * RSA, HMAC-based ID token verification
  * Unsupported features:
    * Aggregated and distributed claims
    * Passing request parameters as JWTs
    * Verification of the `azp` claim (see [discussion](https://bitbucket.org/openid/connect/issues/973/))
    * ECDSA-based ID token verification
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
