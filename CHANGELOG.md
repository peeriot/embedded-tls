# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

- Fix the client accepting a server `Finished` without server authentication (#215). The client now requires a verified `Certificate` and `CertificateVerify`, in that order, or a pre-shared key it offered.
- A `CryptoProvider` that does not override `verifier()` now refuses a server `Certificate` instead of skipping its verification. `UnsecureProvider` returns `NoVerify` explicitly and keeps working; a custom provider that should skip verification must return `NoVerify` from `verifier()`.
- A decrypted record whose plaintext has no non-zero octet (for example a record with only the authentication tag) is now refused with `InvalidRecord` instead of panicking.
- Once the handshake keys are installed, an unprotected record other than `change_cipher_spec` is refused with `InvalidRecord`. A plaintext `close_notify` no longer closes the connection, and a plaintext handshake message no longer reaches the handshake or panics the reader. A protected handshake message other than `NewSessionTicket` after the handshake is refused with `InvalidHandshake` instead of panicking.
- A server `CertificateRequest` after the server's `Certificate`, or after the server selected a pre-shared key, is refused with `InvalidHandshake`; the client no longer sends its certificate in a PSK handshake. A server `Certificate` with an empty certificate list is refused with a `decode_error` alert before the verifier sees it.

## 0.19.0

- Added post-quantum hybrid named groups.
- Add missing implementation to support Client Certificate Authorization (#135)
- Changed edition from 2021 to 2024.
- Add ALPN extension support.
- Move certificate resolution from TlsConfig into CryptoProvider
- Upgrade defmt, embedded-io
- Support RSA signatures
- Add brainpool and ml-dsa signature algorithms
- Add CompressCertificate extension
- Add server chain validation with rust native pki using RustCrypto (rustpki feature)
- Added EcdsaSecp384r1Sha384 and ability to exdend signature schemes
- Introduce a configurable FlushPolicy to control when the TLS layer flushes its underlying transport.

## 0.17.0 - 2024-01-06

- Update to stable rust

## 0.16.3 - 2023-11-04

- Don't block when reading into an empty buffer

## 0.16.2 - 2023-11-02

- Re-add `impl_trait_projections` to support older nightly rustc versions

## 0.16.1 - 2023-10-30

- Corrected recommended read buffer size (16640 bytes instead of 16384)
- Use unwrap macro where possible
- Update to embedded-io 0.6
- Update dependencies

## 0.15.0 - 2023-08-26

- Updated p256 dependency from 0.11 to 0.13.2 (#124)
- Fix reading buffered data in multiple steps (#121, #122)
- Fix error in NewSessionTicket message handling (#120)

## 0.14.1 - 2023-04-29

- Correctly handle transcript of coalesced records, attempt 2.

## 0.14.0 - 2023-04-29

- Refactoring and improving API.
- Support splitting read and write of a connection.
- Properly flush write buffer after handshake.
- Implement BufRead traits for connections.
- Better handling of protocol violations and unsupported features.
- Correctly handle transcript of coalesced records.
