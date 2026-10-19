use crate::config::{TlsCipherSuite, TlsConfig};
use crate::handshake::{ClientHandshake, ServerHandshake};
use crate::key_schedule::{KeySchedule, ReadKeySchedule, WriteKeySchedule};
use crate::record::{ClientRecord, ServerRecord};
use crate::record_reader::RecordReader;
use crate::write_buffer::WriteBuffer;
use crate::{CertificateVerify, CryptoProvider, SignatureScheme, TlsError, TlsVerifier};
use crate::{
    alert::{Alert, AlertDescription, AlertLevel},
    handshake::{certificate::CertificateRef, certificate_request::CertificateRequest},
};
use core::fmt::Debug;
use digest::Digest;
use embedded_io::Error as _;
use embedded_io::{Read as BlockingRead, Write as BlockingWrite};
use embedded_io_async::{Read as AsyncRead, Write as AsyncWrite};

use crate::application_data::ApplicationData;
use crate::buffer::CryptoBuffer;
use hybrid_array::typenum::Unsigned;
use p256::ecdh::EphemeralSecret;
use signature::SignerMut;

use crate::content_types::ContentType;
use crate::parse_buffer::ParseBuffer;
use aes_gcm::aead::{AeadCore, AeadInOut, KeyInit};

/// Decrypts a protected record and passes each message in it to `cb`. Every caller runs after
/// the handshake keys are installed, so an unprotected record is refused unless it is a
/// `ChangeCipherSpec`.
pub(crate) fn decrypt_record<CipherSuite>(
    key_schedule: &mut ReadKeySchedule<CipherSuite>,
    record: ServerRecord<'_, CipherSuite>,
    mut cb: impl FnMut(
        &mut ReadKeySchedule<CipherSuite>,
        ServerRecord<'_, CipherSuite>,
    ) -> Result<(), TlsError>,
) -> Result<(), TlsError>
where
    CipherSuite: TlsCipherSuite,
{
    if let ServerRecord::ApplicationData(ApplicationData {
        header,
        data: mut app_data,
    }) = record
    {
        let server_key = key_schedule.get_key()?;
        let nonce = key_schedule.get_nonce()?;

        let crypto = <CipherSuite::Cipher as KeyInit>::new(server_key);
        crypto
            .decrypt_in_place(&nonce, header.data(), &mut app_data)
            .map_err(|_| TlsError::CryptoError)?;

        // The content type is the last non-zero octet; the zeros after it are padding. A
        // plaintext with no non-zero octet is refused (RFC 8446 section 5.4).
        let (index, &content_type) = app_data
            .as_slice()
            .iter()
            .enumerate()
            .rfind(|(_, b)| **b != 0)
            .ok_or(TlsError::InvalidRecord)?;
        let content_type = ContentType::of(content_type).ok_or(TlsError::InvalidRecord)?;

        trace!("Decrypting: content type = {:?}", content_type);

        // Remove the content type and the padding
        app_data.truncate(index);

        let mut buf = ParseBuffer::new(app_data.as_slice());
        match content_type {
            ContentType::Handshake => {
                // Decode potentially coalesced handshake messages
                while buf.remaining() > 0 {
                    let inner = ServerHandshake::read(&mut buf, key_schedule.transcript_hash())?;
                    cb(key_schedule, ServerRecord::Handshake(inner))?;
                }
            }
            ContentType::ApplicationData => {
                let inner = ApplicationData::new(app_data, header);
                cb(key_schedule, ServerRecord::ApplicationData(inner))?;
            }
            ContentType::Alert => {
                let alert = Alert::parse(&mut buf)?;
                cb(key_schedule, ServerRecord::Alert(alert))?;
            }
            _ => return Err(TlsError::Unimplemented),
        }
        key_schedule.increment_counter();
    } else if let ServerRecord::ChangeCipherSpec(_) = record {
        // A server in middlebox compatibility mode may send an unprotected change_cipher_spec
        // record before its Finished (RFC 8446, Section 5 and Appendix D.4).
        trace!("Not decrypting: content_type = {:?}", record.content_type());
        cb(key_schedule, record)?;
    } else {
        // Once the handshake keys are installed, every other record is protected (RFC 8446,
        // Section 5). An unprotected Handshake or Alert record can come from anyone on the path,
        // so it is refused, and a forged close_notify cannot end the connection (Section 6.1).
        warn!(
            "Unprotected record after the handshake keys: content_type = {:?}",
            record.content_type()
        );
        return Err(TlsError::InvalidRecord);
    }
    Ok(())
}

pub(crate) fn encrypt<CipherSuite>(
    key_schedule: &WriteKeySchedule<CipherSuite>,
    buf: &mut CryptoBuffer<'_>,
) -> Result<(), TlsError>
where
    CipherSuite: TlsCipherSuite,
{
    let client_key = key_schedule.get_key()?;
    let nonce = key_schedule.get_nonce()?;
    // trace!("encrypt key {:02x?}", client_key);
    // trace!("encrypt nonce {:02x?}", nonce);
    // trace!("plaintext {} {:02x?}", buf.len(), buf.as_slice(),);
    //let crypto = Aes128Gcm::new_varkey(&self.key_schedule.get_client_key()).unwrap();
    let crypto = <CipherSuite::Cipher as KeyInit>::new(client_key);
    let len = buf.len() + <CipherSuite::Cipher as AeadCore>::TagSize::to_usize();

    if len > buf.capacity() {
        return Err(TlsError::InsufficientSpace);
    }

    trace!("output size {}", len);
    let len_bytes = (len as u16).to_be_bytes();
    let additional_data = [
        ContentType::ApplicationData as u8,
        0x03,
        0x03,
        len_bytes[0],
        len_bytes[1],
    ];

    crypto
        .encrypt_in_place(&nonce, &additional_data, buf)
        .map_err(|_| TlsError::InvalidApplicationData)
}

pub struct Handshake<CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    traffic_hash: Option<CipherSuite::Hash>,
    secret: Option<EphemeralSecret>,
    certificate_request: Option<CertificateRequest>,
    /// The number of pre-shared key identities the `ClientHello` offered.
    psk_identities: usize,
    server_auth: ServerAuth,
}

impl<CipherSuite> Handshake<CipherSuite>
where
    CipherSuite: TlsCipherSuite,
{
    pub fn new() -> Handshake<CipherSuite> {
        Handshake {
            traffic_hash: None,
            secret: None,
            certificate_request: None,
            psk_identities: 0,
            server_auth: ServerAuth::None,
        }
    }
}

/// How far the server has proven its identity. A valid `Finished` only proves that the peer
/// knows the handshake secret. A peer that chose its own key share always knows it
/// (RFC 8446, Section 4.4).
#[derive(Debug, Clone, Copy, PartialEq)]
enum ServerAuth {
    /// The server has proven nothing yet.
    None,
    /// The verifier accepted the `Certificate`, and its `CertificateVerify` has not arrived.
    Certificate,
    /// The verifier accepted the `CertificateVerify` signature.
    Signed,
    /// The server selected the pre-shared key the client offered.
    Psk,
}

#[derive(Debug, Clone, Copy, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum State {
    ClientHello,
    ServerHello,
    ServerVerify,
    ClientCert,
    ClientCertVerify,
    ClientFinished,
    ApplicationData,
}

impl<'a> State {
    #[allow(clippy::too_many_arguments)]
    pub async fn process<'v, Transport, Provider>(
        self,
        transport: &mut Transport,
        handshake: &mut Handshake<Provider::CipherSuite>,
        record_reader: &mut RecordReader<'_>,
        tx_buf: &mut WriteBuffer<'_>,
        key_schedule: &mut KeySchedule<Provider::CipherSuite>,
        config: &TlsConfig<'a>,
        crypto_provider: &mut Provider,
    ) -> Result<State, TlsError>
    where
        Transport: AsyncRead + AsyncWrite + 'a,
        Provider: CryptoProvider,
    {
        match self {
            State::ClientHello => {
                let (state, tx) =
                    client_hello(key_schedule, config, crypto_provider, tx_buf, handshake)?;

                respond(tx, transport, key_schedule).await?;

                Ok(state)
            }
            State::ServerHello => {
                let record = record_reader
                    .read(transport, key_schedule.read_state())
                    .await?;

                let result = process_server_hello(handshake, key_schedule, record);

                handle_processing_error(result, transport, key_schedule, tx_buf).await
            }
            State::ServerVerify => {
                let record = record_reader
                    .read(transport, key_schedule.read_state())
                    .await?;

                let result =
                    process_server_verify(handshake, key_schedule, crypto_provider, record);

                handle_processing_error(result, transport, key_schedule, tx_buf).await
            }
            State::ClientCert => {
                let (state, tx) = client_cert(handshake, key_schedule, crypto_provider, tx_buf)?;

                respond(tx, transport, key_schedule).await?;

                Ok(state)
            }
            State::ClientCertVerify => {
                let (result, tx) = client_cert_verify(key_schedule, crypto_provider, tx_buf)?;

                respond(tx, transport, key_schedule).await?;

                result
            }
            State::ClientFinished => {
                let tx = client_finished(key_schedule, tx_buf)?;

                respond(tx, transport, key_schedule).await?;

                client_finished_finalize(key_schedule, handshake)
            }
            State::ApplicationData => Ok(State::ApplicationData),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn process_blocking<'v, Transport, Provider>(
        self,
        transport: &mut Transport,
        handshake: &mut Handshake<Provider::CipherSuite>,
        record_reader: &mut RecordReader<'_>,
        tx_buf: &mut WriteBuffer,
        key_schedule: &mut KeySchedule<Provider::CipherSuite>,
        config: &TlsConfig<'a>,
        crypto_provider: &mut Provider,
    ) -> Result<State, TlsError>
    where
        Transport: BlockingRead + BlockingWrite + 'a,
        Provider: CryptoProvider,
    {
        match self {
            State::ClientHello => {
                let (state, tx) =
                    client_hello(key_schedule, config, crypto_provider, tx_buf, handshake)?;

                respond_blocking(tx, transport, key_schedule)?;

                Ok(state)
            }
            State::ServerHello => {
                let record = record_reader.read_blocking(transport, key_schedule.read_state())?;

                let result = process_server_hello(handshake, key_schedule, record);

                handle_processing_error_blocking(result, transport, key_schedule, tx_buf)
            }
            State::ServerVerify => {
                let record = record_reader.read_blocking(transport, key_schedule.read_state())?;

                let result =
                    process_server_verify(handshake, key_schedule, crypto_provider, record);

                handle_processing_error_blocking(result, transport, key_schedule, tx_buf)
            }
            State::ClientCert => {
                let (state, tx) = client_cert(handshake, key_schedule, crypto_provider, tx_buf)?;

                respond_blocking(tx, transport, key_schedule)?;

                Ok(state)
            }
            State::ClientCertVerify => {
                let (result, tx) = client_cert_verify(key_schedule, crypto_provider, tx_buf)?;

                respond_blocking(tx, transport, key_schedule)?;

                result
            }
            State::ClientFinished => {
                let tx = client_finished(key_schedule, tx_buf)?;

                respond_blocking(tx, transport, key_schedule)?;

                client_finished_finalize(key_schedule, handshake)
            }
            State::ApplicationData => Ok(State::ApplicationData),
        }
    }
}

fn handle_processing_error_blocking<CipherSuite>(
    result: Result<State, TlsError>,
    transport: &mut impl BlockingWrite,
    key_schedule: &mut KeySchedule<CipherSuite>,
    tx_buf: &mut WriteBuffer,
) -> Result<State, TlsError>
where
    CipherSuite: TlsCipherSuite,
{
    if let Err(TlsError::AbortHandshake(level, description)) = result {
        let (write_key_schedule, read_key_schedule) = key_schedule.as_split();
        let tx = tx_buf.write_record(
            &ClientRecord::Alert(Alert { level, description }, false),
            write_key_schedule,
            Some(read_key_schedule),
        )?;

        respond_blocking(tx, transport, key_schedule)?;
    }

    result
}

fn respond_blocking<CipherSuite>(
    tx: &[u8],
    transport: &mut impl BlockingWrite,
    key_schedule: &mut KeySchedule<CipherSuite>,
) -> Result<(), TlsError>
where
    CipherSuite: TlsCipherSuite,
{
    transport
        .write_all(tx)
        .map_err(|e| TlsError::Io(e.kind()))?;

    key_schedule.write_state().increment_counter();

    transport.flush().map_err(|e| TlsError::Io(e.kind()))?;

    Ok(())
}

async fn handle_processing_error<CipherSuite>(
    result: Result<State, TlsError>,
    transport: &mut impl AsyncWrite,
    key_schedule: &mut KeySchedule<CipherSuite>,
    tx_buf: &mut WriteBuffer<'_>,
) -> Result<State, TlsError>
where
    CipherSuite: TlsCipherSuite,
{
    if let Err(TlsError::AbortHandshake(level, description)) = result {
        let (write_key_schedule, read_key_schedule) = key_schedule.as_split();
        let tx = tx_buf.write_record(
            &ClientRecord::Alert(Alert { level, description }, false),
            write_key_schedule,
            Some(read_key_schedule),
        )?;

        respond(tx, transport, key_schedule).await?;
    }

    result
}

async fn respond<CipherSuite>(
    tx: &[u8],
    transport: &mut impl AsyncWrite,
    key_schedule: &mut KeySchedule<CipherSuite>,
) -> Result<(), TlsError>
where
    CipherSuite: TlsCipherSuite,
{
    transport
        .write_all(tx)
        .await
        .map_err(|e| TlsError::Io(e.kind()))?;

    key_schedule.write_state().increment_counter();

    transport
        .flush()
        .await
        .map_err(|e| TlsError::Io(e.kind()))?;

    Ok(())
}

fn client_hello<'r, Provider>(
    key_schedule: &mut KeySchedule<Provider::CipherSuite>,
    config: &TlsConfig,
    crypto_provider: &mut Provider,
    tx_buf: &'r mut WriteBuffer,
    handshake: &mut Handshake<Provider::CipherSuite>,
) -> Result<(State, &'r [u8]), TlsError>
where
    Provider: CryptoProvider,
{
    key_schedule.initialize_early_secret(config.psk.as_ref().map(|p| p.0))?;
    handshake.psk_identities = config.psk.as_ref().map_or(0, |p| p.1.len());
    let (write_key_schedule, read_key_schedule) = key_schedule.as_split();
    let client_hello = ClientRecord::client_hello(config, crypto_provider);
    let slice = tx_buf.write_record(&client_hello, write_key_schedule, Some(read_key_schedule))?;

    if let ClientRecord::Handshake(ClientHandshake::ClientHello(client_hello), _) = client_hello {
        handshake.secret.replace(client_hello.secret);
        Ok((State::ServerHello, slice))
    } else {
        Err(TlsError::EncodeError)
    }
}

fn process_server_hello<CipherSuite>(
    handshake: &mut Handshake<CipherSuite>,
    key_schedule: &mut KeySchedule<CipherSuite>,
    record: ServerRecord<'_, CipherSuite>,
) -> Result<State, TlsError>
where
    CipherSuite: TlsCipherSuite,
{
    match record {
        ServerRecord::Handshake(server_handshake) => match server_handshake {
            ServerHandshake::ServerHello(server_hello) => {
                trace!("********* ServerHello");
                let secret = handshake.secret.take().ok_or(TlsError::InvalidHandshake)?;
                let shared = server_hello
                    .calculate_shared_secret(&secret)
                    .ok_or(TlsError::InvalidKeyShare)?;
                if let Some(selected) = server_hello.selected_psk_identity() {
                    // (RFC 8446, Section 4.2.11)
                    //
                    // The selected identity must be one the client offered.
                    if usize::from(selected) >= handshake.psk_identities {
                        return Err(TlsError::InvalidHandshake);
                    }
                    handshake.server_auth = ServerAuth::Psk;
                }
                key_schedule.initialize_handshake_secret(shared.raw_secret_bytes())?;
                Ok(State::ServerVerify)
            }
            _ => Err(TlsError::InvalidHandshake),
        },
        ServerRecord::Alert(alert) => {
            Err(TlsError::HandshakeAborted(alert.level, alert.description))
        }
        _ => Err(TlsError::InvalidRecord),
    }
}

fn process_server_verify<Provider>(
    handshake: &mut Handshake<Provider::CipherSuite>,
    key_schedule: &mut KeySchedule<Provider::CipherSuite>,
    crypto_provider: &mut Provider,
    record: ServerRecord<'_, Provider::CipherSuite>,
) -> Result<State, TlsError>
where
    Provider: CryptoProvider,
{
    let mut state = State::ServerVerify;
    decrypt_record(key_schedule.read_state(), record, |key_schedule, record| {
        match record {
            ServerRecord::Handshake(server_handshake) => {
                match server_handshake {
                    ServerHandshake::EncryptedExtensions(_) => {}
                    ServerHandshake::Certificate(certificate) => {
                        if handshake.server_auth != ServerAuth::None {
                            return Err(TlsError::InvalidHandshake);
                        }
                        // (RFC 8446, Section 4.4.2.4)
                        //
                        // A server that authenticates with a certificate must send one. An
                        // empty certificate_list is refused with decode_error before the
                        // verifier sees it, so no verifier can take it as authentication.
                        if certificate.entries.is_empty() {
                            warn!("Certificate refused: the certificate_list is empty");
                            return Err(TlsError::AbortHandshake(
                                AlertLevel::Fatal,
                                AlertDescription::DecodeError,
                            ));
                        }
                        //
                        // The client must verify the server's certificate, so a provider
                        // without a verifier cannot accept one. `NoVerify` skips the check
                        // only when the provider returns it explicitly.
                        let verifier = crypto_provider.verifier().map_err(|_| {
                            warn!("Certificate refused: the provider has no verifier");
                            TlsError::InvalidHandshake
                        })?;
                        let transcript = key_schedule.transcript_hash();
                        verifier.verify_certificate(transcript, certificate)?;
                        debug!("Certificate verified!");
                        handshake.server_auth = ServerAuth::Certificate;
                    }
                    ServerHandshake::CertificateVerify(verify) => {
                        if handshake.server_auth != ServerAuth::Certificate {
                            return Err(TlsError::InvalidHandshake);
                        }
                        // (RFC 8446, Section 4.4.3)
                        //
                        // The client must verify the signature with the certificate's key.
                        let verifier = crypto_provider.verifier().map_err(|_| {
                            warn!("CertificateVerify refused: the provider has no verifier");
                            TlsError::InvalidHandshake
                        })?;
                        verifier.verify_signature(verify)?;
                        debug!("Signature verified!");
                        handshake.server_auth = ServerAuth::Signed;
                    }
                    ServerHandshake::CertificateRequest(request) => {
                        // (RFC 8446, Section 4.3.2)
                        //
                        // A CertificateRequest comes right after EncryptedExtensions, before
                        // the server's Certificate, and a server that authenticates with a
                        // pre-shared key must not send one. The handshake has room for one
                        // CertificateRequest only, so a second one is refused too.
                        if handshake.server_auth != ServerAuth::None {
                            warn!("CertificateRequest refused: the server already authenticated");
                            return Err(TlsError::InvalidHandshake);
                        }
                        if handshake.certificate_request.is_some() {
                            warn!("CertificateRequest refused: the server already sent one");
                            return Err(TlsError::InvalidHandshake);
                        }
                        handshake.certificate_request.replace(request.try_into()?);
                    }
                    ServerHandshake::Finished(finished) => {
                        if !matches!(handshake.server_auth, ServerAuth::Signed | ServerAuth::Psk) {
                            warn!("Finished before the server authenticated");
                            return Err(TlsError::InvalidHandshake);
                        }
                        if !key_schedule.verify_server_finished(&finished)? {
                            warn!("Server signature verification failed");
                            return Err(TlsError::InvalidSignature);
                        }

                        // trace!("server verified {}", verified);
                        state = if handshake.certificate_request.is_some() {
                            State::ClientCert
                        } else {
                            handshake
                                .traffic_hash
                                .replace(key_schedule.transcript_hash().clone());
                            State::ClientFinished
                        };
                    }
                    _ => return Err(TlsError::InvalidHandshake),
                }
            }
            ServerRecord::ChangeCipherSpec(_) => {}
            _ => return Err(TlsError::InvalidRecord),
        }

        Ok(())
    })?;
    Ok(state)
}

fn client_cert<'r, Provider>(
    handshake: &mut Handshake<Provider::CipherSuite>,
    key_schedule: &mut KeySchedule<Provider::CipherSuite>,
    crypto_provider: &mut Provider,
    buffer: &'r mut WriteBuffer,
) -> Result<(State, &'r [u8]), TlsError>
where
    Provider: CryptoProvider,
{
    handshake
        .traffic_hash
        .replace(key_schedule.transcript_hash().clone());

    let request_context = &handshake
        .certificate_request
        .as_ref()
        .ok_or(TlsError::InvalidHandshake)?
        .request_context;

    // Declare cert before certificate so owned data outlives the CertificateRef that borrows it
    let cert = crypto_provider.client_cert();
    let mut certificate = CertificateRef::with_context(request_context);
    let next_state = if let Some(ref cert) = cert {
        certificate.add(cert.into())?;
        State::ClientCertVerify
    } else {
        State::ClientFinished
    };
    let (write_key_schedule, read_key_schedule) = key_schedule.as_split();

    buffer
        .write_record(
            &ClientRecord::Handshake(ClientHandshake::ClientCert(certificate), true),
            write_key_schedule,
            Some(read_key_schedule),
        )
        .map(|slice| (next_state, slice))
}

/// The content that the client's `CertificateVerify` signs (RFC 8446 section 4.4.3): 64 spaces,
/// the context string with its zero byte, then the transcript hash.
fn certificate_verify_content(transcript_hash: &[u8]) -> Result<heapless::Vec<u8, 146>, TlsError> {
    const CONTEXT: &[u8] = b"TLS 1.3, client CertificateVerify\x00";

    // 64 (pad) + 34 (ctx) + 48 (SHA-384) = 146 bytes required
    let mut content: heapless::Vec<u8, 146> = heapless::Vec::new();
    content
        .resize(64, 0x20)
        .map_err(|_| TlsError::EncodeError)?;
    content
        .extend_from_slice(CONTEXT)
        .map_err(|_| TlsError::EncodeError)?;
    content
        .extend_from_slice(transcript_hash)
        .map_err(|_| TlsError::EncodeError)?;
    Ok(content)
}

/// Signs the client's `CertificateVerify` over `transcript_hash` with `signer`.
///
/// It calls `try_sign`, not `sign`, which panics when signing fails: an error of the signer, of
/// its RNG or of a hardware key is returned as `CryptoError`, and a signature that does not fit
/// the message as `EncodeError`.
fn sign_certificate_verify<S: AsRef<[u8]>>(
    signer: &mut impl SignerMut<S>,
    signature_scheme: SignatureScheme,
    transcript_hash: &[u8],
) -> Result<CertificateVerify, TlsError> {
    let content = certificate_verify_content(transcript_hash)?;
    let signature = signer
        .try_sign(&content)
        .map_err(|_| TlsError::CryptoError)?;

    trace!(
        "Signature: {:?} ({})",
        signature.as_ref(),
        signature.as_ref().len()
    );

    Ok(CertificateVerify {
        signature_scheme,
        signature: heapless::Vec::from_slice(signature.as_ref())
            .map_err(|_| TlsError::EncodeError)?,
    })
}

fn client_cert_verify<'r, Provider>(
    key_schedule: &mut KeySchedule<Provider::CipherSuite>,
    crypto_provider: &mut Provider,
    buffer: &'r mut WriteBuffer,
) -> Result<(Result<State, TlsError>, &'r [u8]), TlsError>
where
    Provider: CryptoProvider,
{
    let transcript_hash = key_schedule.transcript_hash().clone().finalize();
    let signed = crypto_provider
        .signer()
        .and_then(|(mut signer, signature_scheme)| {
            sign_certificate_verify(&mut signer, signature_scheme, transcript_hash.as_slice())
        });

    let (result, record) = match signed {
        Ok(certificate_verify) => (
            Ok(State::ClientFinished),
            ClientRecord::Handshake(ClientHandshake::ClientCertVerify(certificate_verify), true),
        ),
        Err(e) => {
            error!("Failed to sign the client CertificateVerify: {:?}", e);
            (
                Err(e),
                ClientRecord::Alert(
                    Alert::new(AlertLevel::Warning, AlertDescription::CloseNotify),
                    true,
                ),
            )
        }
    };

    let (write_key_schedule, read_key_schedule) = key_schedule.as_split();

    buffer
        .write_record(&record, write_key_schedule, Some(read_key_schedule))
        .map(|slice| (result, slice))
}

fn client_finished<'r, CipherSuite>(
    key_schedule: &mut KeySchedule<CipherSuite>,
    buffer: &'r mut WriteBuffer,
) -> Result<&'r [u8], TlsError>
where
    CipherSuite: TlsCipherSuite,
{
    let client_finished = key_schedule
        .create_client_finished()
        .map_err(|_| TlsError::InvalidHandshake)?;

    let (write_key_schedule, read_key_schedule) = key_schedule.as_split();

    buffer.write_record(
        &ClientRecord::Handshake(ClientHandshake::Finished(client_finished), true),
        write_key_schedule,
        Some(read_key_schedule),
    )
}

fn client_finished_finalize<CipherSuite>(
    key_schedule: &mut KeySchedule<CipherSuite>,
    handshake: &mut Handshake<CipherSuite>,
) -> Result<State, TlsError>
where
    CipherSuite: TlsCipherSuite,
{
    key_schedule.replace_transcript_hash(
        handshake
            .traffic_hash
            .take()
            .ok_or(TlsError::InvalidHandshake)?,
    );
    key_schedule.initialize_master_secret()?;

    Ok(State::ApplicationData)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::UnsecureProvider;
    use crate::common::decrypted_buffer_info::DecryptedBufferInfo;
    use crate::common::decrypted_read_handler::DecryptedReadHandler;
    use crate::config::{Aes128GcmSha256, CertificateVerifyRef, TlsVerifier};
    use crate::handshake::HandshakeType;
    use crate::handshake::server_hello::ServerHello;
    use getrandom::SysRng;
    use p256::elliptic_curve::Generate;
    use rand_core::UnwrapErr;

    type Suite = Aes128GcmSha256;
    type Cipher = <Suite as TlsCipherSuite>::Cipher;

    /// A provider whose verifier accepts any certificate and any signature, like the
    /// `InsecureNoVerify` verifier of later releases. The tests that use it check only the order
    /// of the messages.
    struct InsecureNoVerify;

    impl CryptoProvider for InsecureNoVerify {
        type CipherSuite = Suite;
        type Signature = p256::ecdsa::DerSignature;

        fn rng(&mut self) -> impl crate::CryptoRng {
            UnwrapErr(SysRng)
        }

        fn verifier(&mut self) -> Result<&mut impl TlsVerifier<Suite>, TlsError> {
            Ok(self)
        }
    }

    impl TlsVerifier<Suite> for InsecureNoVerify {
        fn set_hostname_verification(&mut self, _hostname: &str) -> Result<(), TlsError> {
            Ok(())
        }

        fn verify_certificate(
            &mut self,
            _transcript: &<Suite as TlsCipherSuite>::Hash,
            _cert: CertificateRef,
        ) -> Result<(), TlsError> {
            Ok(())
        }

        fn verify_signature(&mut self, _verify: CertificateVerifyRef) -> Result<(), TlsError> {
            Ok(())
        }
    }

    /// The client's state after a `ServerHello` from a peer that chose its own key share, so the
    /// peer knows the handshake secret.
    fn after_server_hello() -> (Handshake<Suite>, KeySchedule<Suite>) {
        let mut key_schedule = KeySchedule::new();
        key_schedule.initialize_early_secret(None).unwrap();
        key_schedule.initialize_handshake_secret(&[7; 32]).unwrap();
        (Handshake::new(), key_schedule)
    }

    /// The bytes of a handshake message: its type, its length, then `body`.
    fn handshake_message(handshake_type: HandshakeType, body: &[u8]) -> std::vec::Vec<u8> {
        let mut message = std::vec![handshake_type as u8];
        message.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        message.extend_from_slice(body);
        message
    }

    fn finished(key_schedule: &mut KeySchedule<Suite>) -> std::vec::Vec<u8> {
        let finished = key_schedule.read_state().server_finished().unwrap();
        assert!(
            key_schedule
                .read_state()
                .verify_server_finished(&finished)
                .unwrap()
        );
        handshake_message(HandshakeType::Finished, finished.verify.as_ref())
    }

    /// A `Certificate` with no request context and one made-up certificate entry.
    fn certificate() -> std::vec::Vec<u8> {
        handshake_message(
            HandshakeType::Certificate,
            &[0, 0, 0, 7, 0, 0, 2, 0x30, 0x00, 0, 0],
        )
    }

    /// A `Certificate` with no request context and an empty `certificate_list`.
    fn empty_certificate() -> std::vec::Vec<u8> {
        handshake_message(HandshakeType::Certificate, &[0, 0, 0, 0])
    }

    /// A `CertificateRequest` with no request context and no extensions.
    fn certificate_request() -> std::vec::Vec<u8> {
        handshake_message(HandshakeType::CertificateRequest, &[0, 0, 0])
    }

    /// A `CertificateVerify` with a made-up `ecdsa_secp256r1_sha256` signature.
    fn certificate_verify() -> std::vec::Vec<u8> {
        let mut body = std::vec![0x04, 0x03, 0, 64];
        body.extend_from_slice(&[1; 64]);
        handshake_message(HandshakeType::CertificateVerify, &body)
    }

    /// Seals `message` in a record with the server's handshake traffic key, as the server does,
    /// and passes the record to `process_server_verify` with `provider`.
    fn verify_with<Provider: CryptoProvider<CipherSuite = Suite>>(
        handshake: &mut Handshake<Suite>,
        key_schedule: &mut KeySchedule<Suite>,
        provider: &mut Provider,
        message: &[u8],
    ) -> Result<State, TlsError> {
        let mut plaintext = message.to_vec();
        plaintext.push(ContentType::Handshake as u8);
        let mut bytes = sealed_record_bytes(key_schedule.read_state(), &plaintext)?;
        let record = parse_record(key_schedule.read_state(), &mut bytes)?;
        process_server_verify(handshake, key_schedule, provider, record)
    }

    /// `verify_with` with `InsecureNoVerify`, which accepts any certificate and any signature,
    /// so the tests that use it check only the order of the messages.
    fn verify(
        handshake: &mut Handshake<Suite>,
        key_schedule: &mut KeySchedule<Suite>,
        message: &[u8],
    ) -> Result<State, TlsError> {
        verify_with(handshake, key_schedule, &mut InsecureNoVerify, message)
    }

    #[test]
    fn finished_without_a_certificate_is_refused() {
        let (mut handshake, mut key_schedule) = after_server_hello();
        let message = finished(&mut key_schedule);
        let result = verify(&mut handshake, &mut key_schedule, &message);
        assert!(
            matches!(result, Err(TlsError::InvalidHandshake)),
            "{result:?}"
        );
    }

    #[test]
    fn certificate_then_certificate_verify_then_finished_is_accepted() {
        let (mut handshake, mut key_schedule) = after_server_hello();
        for message in [certificate(), certificate_verify()] {
            let result = verify(&mut handshake, &mut key_schedule, &message);
            assert!(matches!(result, Ok(State::ServerVerify)), "{result:?}");
        }
        let message = finished(&mut key_schedule);
        let result = verify(&mut handshake, &mut key_schedule, &message);
        assert!(matches!(result, Ok(State::ClientFinished)), "{result:?}");
    }

    #[test]
    fn a_certificate_after_a_selected_psk_is_refused() {
        let (mut handshake, mut key_schedule) = after_server_hello();
        handshake.server_auth = ServerAuth::Psk;
        let result = verify(&mut handshake, &mut key_schedule, &certificate());
        assert!(
            matches!(result, Err(TlsError::InvalidHandshake)),
            "{result:?}"
        );
    }

    #[test]
    fn finished_after_a_verified_signature_is_accepted() {
        let (mut handshake, mut key_schedule) = after_server_hello();
        handshake.server_auth = ServerAuth::Signed;
        let message = finished(&mut key_schedule);
        let result = verify(&mut handshake, &mut key_schedule, &message);
        assert!(matches!(result, Ok(State::ClientFinished)), "{result:?}");
    }

    #[test]
    fn finished_after_a_selected_psk_is_accepted() {
        let (mut handshake, mut key_schedule) = after_server_hello();
        handshake.server_auth = ServerAuth::Psk;
        let message = finished(&mut key_schedule);
        let result = verify(&mut handshake, &mut key_schedule, &message);
        assert!(matches!(result, Ok(State::ClientFinished)), "{result:?}");
    }

    #[test]
    fn finished_after_a_certificate_without_its_signature_is_refused() {
        let (mut handshake, mut key_schedule) = after_server_hello();
        handshake.server_auth = ServerAuth::Certificate;
        let message = finished(&mut key_schedule);
        let result = verify(&mut handshake, &mut key_schedule, &message);
        assert!(
            matches!(result, Err(TlsError::InvalidHandshake)),
            "{result:?}"
        );
    }

    #[test]
    fn certificate_verify_after_a_certificate_authenticates_the_server() {
        let (mut handshake, mut key_schedule) = after_server_hello();
        handshake.server_auth = ServerAuth::Certificate;
        let result = verify(&mut handshake, &mut key_schedule, &certificate_verify());
        assert!(matches!(result, Ok(State::ServerVerify)), "{result:?}");
        assert_eq!(handshake.server_auth, ServerAuth::Signed);
    }

    /// A `ServerHello` with a P-256 key share from a fresh key, and with a `pre_shared_key`
    /// extension that selects the identity `psk` when it is set.
    fn server_hello(psk: Option<u16>) -> std::vec::Vec<u8> {
        let key = p256::Sec1Point::from(
            EphemeralSecret::generate_from_rng(&mut UnwrapErr(SysRng)).public_key(),
        );
        let key = key.as_bytes();
        let mut extensions = std::vec::Vec::new();
        extensions.extend_from_slice(&[0x00, 0x33]);
        extensions.extend_from_slice(&(4 + key.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&[0x00, 0x17]);
        extensions.extend_from_slice(&(key.len() as u16).to_be_bytes());
        extensions.extend_from_slice(key);
        if let Some(identity) = psk {
            extensions.extend_from_slice(&[0x00, 0x29, 0x00, 0x02]);
            extensions.extend_from_slice(&identity.to_be_bytes());
        }
        let mut hello = std::vec![0x03, 0x03];
        hello.extend_from_slice(&[0; 32]);
        hello.extend_from_slice(&[0x00, 0x13, 0x01, 0x00]);
        hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        hello.extend_from_slice(&extensions);
        hello
    }

    fn process_hello(handshake: &mut Handshake<Suite>, bytes: &[u8]) -> Result<State, TlsError> {
        handshake.secret = Some(EphemeralSecret::generate_from_rng(&mut UnwrapErr(SysRng)));
        let hello = ServerHello::parse(&mut ParseBuffer::new(bytes)).unwrap();
        let mut key_schedule = KeySchedule::new();
        key_schedule.initialize_early_secret(None).unwrap();
        process_server_hello(
            handshake,
            &mut key_schedule,
            ServerRecord::Handshake(ServerHandshake::ServerHello(hello)),
        )
    }

    #[test]
    fn a_selected_psk_that_was_not_offered_is_refused() {
        let mut handshake = Handshake::new();
        let result = process_hello(&mut handshake, &server_hello(Some(0)));
        assert!(
            matches!(result, Err(TlsError::InvalidHandshake)),
            "{result:?}"
        );
    }

    #[test]
    fn a_selected_psk_identity_past_the_offered_ones_is_refused() {
        let mut handshake = Handshake::new();
        handshake.psk_identities = 1;
        let result = process_hello(&mut handshake, &server_hello(Some(1)));
        assert!(
            matches!(result, Err(TlsError::InvalidHandshake)),
            "{result:?}"
        );
    }

    #[test]
    fn a_selected_psk_that_was_offered_authenticates_the_server() {
        let mut handshake = Handshake::new();
        handshake.psk_identities = 2;
        let result = process_hello(&mut handshake, &server_hello(Some(1)));
        assert!(matches!(result, Ok(State::ServerVerify)), "{result:?}");
        assert_eq!(handshake.server_auth, ServerAuth::Psk);
    }

    #[test]
    fn a_hello_without_a_psk_leaves_the_server_unauthenticated() {
        let mut handshake = Handshake::new();
        handshake.psk_identities = 1;
        let result = process_hello(&mut handshake, &server_hello(None));
        assert!(matches!(result, Ok(State::ServerVerify)), "{result:?}");
        assert_eq!(handshake.server_auth, ServerAuth::None);
    }

    #[test]
    fn certificate_verify_without_a_certificate_is_refused() {
        let (mut handshake, mut key_schedule) = after_server_hello();
        let result = verify(&mut handshake, &mut key_schedule, &certificate_verify());
        assert!(
            matches!(result, Err(TlsError::InvalidHandshake)),
            "{result:?}"
        );
    }

    /// A provider that keeps the default `verifier()`, which returns an error.
    struct WithoutVerifier;

    impl CryptoProvider for WithoutVerifier {
        type CipherSuite = Suite;
        type Signature = p256::ecdsa::DerSignature;

        fn rng(&mut self) -> impl crate::CryptoRng {
            UnwrapErr(SysRng)
        }
    }

    #[test]
    fn a_certificate_is_refused_by_a_provider_without_a_verifier() {
        let (mut handshake, mut key_schedule) = after_server_hello();
        let result = verify_with(
            &mut handshake,
            &mut key_schedule,
            &mut WithoutVerifier,
            &certificate(),
        );
        assert!(
            matches!(result, Err(TlsError::InvalidHandshake)),
            "{result:?}"
        );
        assert_eq!(handshake.server_auth, ServerAuth::None);
    }

    #[test]
    fn a_certificate_verify_is_refused_by_a_provider_without_a_verifier() {
        let (mut handshake, mut key_schedule) = after_server_hello();
        handshake.server_auth = ServerAuth::Certificate;
        let result = verify_with(
            &mut handshake,
            &mut key_schedule,
            &mut WithoutVerifier,
            &certificate_verify(),
        );
        assert!(
            matches!(result, Err(TlsError::InvalidHandshake)),
            "{result:?}"
        );
        assert_eq!(handshake.server_auth, ServerAuth::Certificate);
    }

    /// `UnsecureProvider` opts out of verification explicitly with `NoVerify`.
    #[test]
    fn certificate_then_certificate_verify_then_finished_is_accepted_by_unsecure_provider() {
        let (mut handshake, mut key_schedule) = after_server_hello();
        let mut provider = UnsecureProvider::new::<Suite>(UnwrapErr(SysRng));
        for message in [certificate(), certificate_verify()] {
            let result = verify_with(&mut handshake, &mut key_schedule, &mut provider, &message);
            assert!(matches!(result, Ok(State::ServerVerify)), "{result:?}");
        }
        let message = finished(&mut key_schedule);
        let result = verify_with(&mut handshake, &mut key_schedule, &mut provider, &message);
        assert!(matches!(result, Ok(State::ClientFinished)), "{result:?}");
    }

    #[test]
    fn a_certificate_request_before_the_certificate_asks_for_a_client_certificate() {
        let (mut handshake, mut key_schedule) = after_server_hello();
        for message in [certificate_request(), certificate(), certificate_verify()] {
            let result = verify(&mut handshake, &mut key_schedule, &message);
            assert!(matches!(result, Ok(State::ServerVerify)), "{result:?}");
        }
        let message = finished(&mut key_schedule);
        let result = verify(&mut handshake, &mut key_schedule, &message);
        assert!(matches!(result, Ok(State::ClientCert)), "{result:?}");
    }

    /// RFC 8446, Section 4.3.2: a server that authenticates with a pre-shared key must not send
    /// a `CertificateRequest`.
    #[test]
    fn a_certificate_request_after_a_selected_psk_is_refused() {
        let (mut handshake, mut key_schedule) = after_server_hello();
        handshake.server_auth = ServerAuth::Psk;
        let result = verify(&mut handshake, &mut key_schedule, &certificate_request());
        assert!(
            matches!(result, Err(TlsError::InvalidHandshake)),
            "{result:?}"
        );
        assert!(handshake.certificate_request.is_none());
    }

    /// RFC 8446, Section 4.3.2: a `CertificateRequest` comes before the server's `Certificate`.
    #[test]
    fn a_certificate_request_after_the_certificate_is_refused() {
        for messages in [
            std::vec![certificate()],
            std::vec![certificate(), certificate_verify()],
        ] {
            let (mut handshake, mut key_schedule) = after_server_hello();
            for message in messages {
                let result = verify(&mut handshake, &mut key_schedule, &message);
                assert!(matches!(result, Ok(State::ServerVerify)), "{result:?}");
            }
            let result = verify(&mut handshake, &mut key_schedule, &certificate_request());
            assert!(
                matches!(result, Err(TlsError::InvalidHandshake)),
                "{result:?}"
            );
            assert!(handshake.certificate_request.is_none());
        }
    }

    /// RFC 8446, Section 4.3.2: the server sends at most one `CertificateRequest`, right after
    /// `EncryptedExtensions`, so a second one is refused.
    #[test]
    fn a_second_certificate_request_is_refused() {
        let (mut handshake, mut key_schedule) = after_server_hello();
        let result = verify(&mut handshake, &mut key_schedule, &certificate_request());
        assert!(matches!(result, Ok(State::ServerVerify)), "{result:?}");
        let result = verify(&mut handshake, &mut key_schedule, &certificate_request());
        assert!(
            matches!(result, Err(TlsError::InvalidHandshake)),
            "{result:?}"
        );
        assert!(handshake.certificate_request.is_some());
    }

    /// RFC 8446, Section 4.4.2.4: an empty `certificate_list` is refused with `decode_error`,
    /// even by a verifier that accepts any certificate.
    #[test]
    fn an_empty_certificate_list_is_refused() {
        let (mut handshake, mut key_schedule) = after_server_hello();
        let result = verify(&mut handshake, &mut key_schedule, &empty_certificate());
        assert!(
            matches!(
                result,
                Err(TlsError::AbortHandshake(
                    AlertLevel::Fatal,
                    AlertDescription::DecodeError
                ))
            ),
            "{result:?}"
        );
        assert_eq!(handshake.server_auth, ServerAuth::None);
    }

    /// The empty `certificate_list` is refused before the provider is asked for a verifier.
    #[test]
    fn an_empty_certificate_list_is_refused_before_the_verifier() {
        let (mut handshake, mut key_schedule) = after_server_hello();
        let result = verify_with(
            &mut handshake,
            &mut key_schedule,
            &mut WithoutVerifier,
            &empty_certificate(),
        );
        assert!(
            matches!(
                result,
                Err(TlsError::AbortHandshake(
                    AlertLevel::Fatal,
                    AlertDescription::DecodeError
                ))
            ),
            "{result:?}"
        );
        assert_eq!(handshake.server_auth, ServerAuth::None);
    }

    /// The bytes of a record: its header, then `fragment`.
    fn record_bytes(content_type: ContentType, fragment: &[u8]) -> std::vec::Vec<u8> {
        let mut bytes = std::vec![content_type as u8, 0x03, 0x03];
        bytes.extend_from_slice(&(fragment.len() as u16).to_be_bytes());
        bytes.extend_from_slice(fragment);
        bytes
    }

    /// The bytes of a protected record that holds `plaintext` (the content, its content type,
    /// then any zero padding), sealed with the server's handshake traffic key, as a peer that
    /// knows the handshake secret can.
    fn sealed_record_bytes(
        read: &mut ReadKeySchedule<Suite>,
        plaintext: &[u8],
    ) -> Result<std::vec::Vec<u8>, TlsError> {
        let mut bytes = record_bytes(ContentType::ApplicationData, plaintext);
        let tag_len = <Cipher as AeadCore>::TagSize::to_usize();
        let len = ((plaintext.len() + tag_len) as u16).to_be_bytes();
        bytes[3..5].copy_from_slice(&len);
        let (header, data) = bytes.split_at_mut(crate::record::RecordHeader::LEN);
        let crypto = <Cipher as KeyInit>::new(read.get_key()?);
        let tag = crypto
            .encrypt_inout_detached(&read.get_nonce()?, header, data.into())
            .map_err(|_| TlsError::CryptoError)?;
        bytes.extend_from_slice(&tag);
        Ok(bytes)
    }

    /// Parses the record in `bytes`, as the record reader does.
    fn parse_record<'a>(
        read: &mut ReadKeySchedule<Suite>,
        bytes: &'a mut [u8],
    ) -> Result<ServerRecord<'a, Suite>, TlsError> {
        let (header, data) = bytes.split_at_mut(crate::record::RecordHeader::LEN);
        let header = crate::record::RecordHeader::decode(
            (&*header).try_into().map_err(|_| TlsError::InvalidRecord)?,
        )?;
        ServerRecord::decode(header, data, read.transcript_hash())
    }

    /// Seals `plaintext` (the content, its content type, then any zero padding) with the server's
    /// handshake traffic key, as a peer that knows the handshake secret can, and decrypts it.
    /// Returns the content type and the content of each record that `decrypt_record` passes on.
    fn open_sealed(
        plaintext: &[u8],
    ) -> Result<std::vec::Vec<(ContentType, std::vec::Vec<u8>)>, TlsError> {
        let (_, mut key_schedule) = after_server_hello();
        let read = key_schedule.read_state();
        let mut bytes = sealed_record_bytes(read, plaintext)?;
        let record = parse_record(read, &mut bytes)?;
        let mut records = std::vec::Vec::new();
        decrypt_record(read, record, |_, record| {
            let content = match &record {
                ServerRecord::ApplicationData(app_data) => app_data.data.as_slice().to_vec(),
                _ => std::vec::Vec::new(),
            };
            records.push((record.content_type(), content));
            Ok(())
        })?;
        Ok(records)
    }

    #[test]
    fn a_padded_record_is_opened() {
        let records = open_sealed(&[b'h', b'i', ContentType::ApplicationData as u8, 0, 0]);
        assert!(
            matches!(
                records.as_deref(),
                Ok([(ContentType::ApplicationData, content)]) if content == b"hi"
            ),
            "{records:?}"
        );
    }

    #[test]
    fn a_record_with_only_a_tag_is_refused() {
        let records = open_sealed(&[]);
        assert!(
            matches!(records, Err(TlsError::InvalidRecord)),
            "{records:?}"
        );
    }

    #[test]
    fn a_record_with_only_padding_is_refused() {
        let records = open_sealed(&[0; 8]);
        assert!(
            matches!(records, Err(TlsError::InvalidRecord)),
            "{records:?}"
        );
    }

    const CLOSE_NOTIFY: [u8; 2] = [
        AlertLevel::Warning as u8,
        AlertDescription::CloseNotify as u8,
    ];

    /// Reads one record with `content_type` and `content` the way a connection reads application
    /// data, and returns the result and whether the connection is still open. The record is
    /// sealed with the read key when `protected` is set, and sent in the clear otherwise. Which
    /// traffic key is installed does not matter to `decrypt_record` or the handler.
    fn read_application_data(
        protected: bool,
        content_type: ContentType,
        content: &[u8],
    ) -> (Result<(), TlsError>, bool) {
        let (_, mut key_schedule) = after_server_hello();
        let read = key_schedule.read_state();
        let mut bytes = if protected {
            let mut plaintext = content.to_vec();
            plaintext.push(content_type as u8);
            sealed_record_bytes(read, &plaintext).unwrap()
        } else {
            record_bytes(content_type, content)
        };
        let source_buffer = bytes.as_ptr_range();
        let record = parse_record(read, &mut bytes).unwrap();
        let mut buffer_info = DecryptedBufferInfo::default();
        let mut is_open = true;
        let mut handler = DecryptedReadHandler {
            source_buffer,
            buffer_info: &mut buffer_info,
            is_open: &mut is_open,
        };
        let result = decrypt_record(read, record, |_, record| handler.handle(record));
        (result, is_open)
    }

    #[test]
    fn a_protected_close_notify_closes_the_connection() {
        let (result, is_open) = read_application_data(true, ContentType::Alert, &CLOSE_NOTIFY);
        assert!(
            matches!(result, Err(TlsError::ConnectionClosed)),
            "{result:?}"
        );
        assert!(!is_open);
    }

    #[test]
    fn a_plaintext_close_notify_is_refused_and_leaves_the_connection_open() {
        let (result, is_open) = read_application_data(false, ContentType::Alert, &CLOSE_NOTIFY);
        assert!(matches!(result, Err(TlsError::InvalidRecord)), "{result:?}");
        assert!(is_open);
    }

    #[test]
    fn a_plaintext_handshake_message_after_the_handshake_is_refused() {
        let (result, is_open) =
            read_application_data(false, ContentType::Handshake, &certificate());
        assert!(matches!(result, Err(TlsError::InvalidRecord)), "{result:?}");
        assert!(is_open);
    }

    #[test]
    fn a_protected_certificate_after_the_handshake_is_refused() {
        let (result, _) = read_application_data(true, ContentType::Handshake, &certificate());
        assert!(
            matches!(result, Err(TlsError::InvalidHandshake)),
            "{result:?}"
        );
    }

    #[test]
    fn a_plaintext_certificate_during_the_handshake_is_refused() {
        let (mut handshake, mut key_schedule) = after_server_hello();
        let mut bytes = record_bytes(ContentType::Handshake, &certificate());
        let record = parse_record(key_schedule.read_state(), &mut bytes).unwrap();
        let result = process_server_verify(
            &mut handshake,
            &mut key_schedule,
            &mut InsecureNoVerify,
            record,
        );
        assert!(matches!(result, Err(TlsError::InvalidRecord)), "{result:?}");
        assert_eq!(handshake.server_auth, ServerAuth::None);
    }

    #[test]
    fn a_plaintext_change_cipher_spec_during_the_handshake_is_dropped() {
        let (mut handshake, mut key_schedule) = after_server_hello();
        let mut bytes = record_bytes(ContentType::ChangeCipherSpec, &[1]);
        let record = parse_record(key_schedule.read_state(), &mut bytes).unwrap();
        let result = process_server_verify(
            &mut handshake,
            &mut key_schedule,
            &mut InsecureNoVerify,
            record,
        );
        assert!(matches!(result, Ok(State::ServerVerify)), "{result:?}");
        assert_eq!(handshake.server_auth, ServerAuth::None);
    }

    /// The P-256 client key of the integration tests, as SEC1 DER.
    fn client_key_der() -> std::vec::Vec<u8> {
        pem_parser::pem_to_der(include_str!("../tests/data/client-key.pem"))
    }

    /// A provider that signs the client `CertificateVerify` with `signer`.
    struct SignWith<F>(F);

    impl<F, Signer> CryptoProvider for SignWith<F>
    where
        F: FnMut() -> Signer,
        Signer: SignerMut<p256::ecdsa::DerSignature>,
    {
        type CipherSuite = Suite;
        type Signature = p256::ecdsa::DerSignature;

        fn rng(&mut self) -> impl crate::CryptoRng {
            UnwrapErr(SysRng)
        }

        fn signer(
            &mut self,
        ) -> Result<(impl SignerMut<Self::Signature>, SignatureScheme), TlsError> {
            Ok(((self.0)(), SignatureScheme::EcdsaSecp256r1Sha256))
        }
    }

    /// An RNG that always fails, like a hardware RNG that stopped working.
    struct FailingRng;

    #[derive(Debug)]
    struct RngFailure;

    impl core::fmt::Display for RngFailure {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.write_str("RNG failure")
        }
    }

    impl core::error::Error for RngFailure {}

    impl rand_core::TryRng for FailingRng {
        type Error = RngFailure;

        fn try_next_u32(&mut self) -> Result<u32, RngFailure> {
            Err(RngFailure)
        }

        fn try_next_u64(&mut self) -> Result<u64, RngFailure> {
            Err(RngFailure)
        }

        fn try_fill_bytes(&mut self, _dst: &mut [u8]) -> Result<(), RngFailure> {
            Err(RngFailure)
        }
    }

    impl rand_core::TryCryptoRng for FailingRng {}

    /// Runs `client_cert_verify` with `provider` in the state of `after_server_hello`, so every
    /// call signs the same transcript, and opens the record it writes with the client's
    /// handshake traffic key, as the server does. Returns the result, the transcript hash and
    /// the record's plaintext (the message, then its content type).
    fn certificate_verify_record<Provider: CryptoProvider<CipherSuite = Suite>>(
        provider: &mut Provider,
    ) -> (
        Result<State, TlsError>,
        std::vec::Vec<u8>,
        std::vec::Vec<u8>,
    ) {
        let (_, mut key_schedule) = after_server_hello();
        let transcript_hash = key_schedule.transcript_hash().clone().finalize().to_vec();
        let mut buf = [0; 1024];
        let mut buffer = WriteBuffer::new(&mut buf);
        let (result, record) =
            client_cert_verify(&mut key_schedule, provider, &mut buffer).unwrap();
        let mut record = record.to_vec();

        // The server's view of the client's handshake traffic key, before any record.
        let (_, mut server) = after_server_hello();
        let write = server.write_state();
        let (header, data) = record.split_at_mut(crate::record::RecordHeader::LEN);
        let tag_len = <Cipher as AeadCore>::TagSize::to_usize();
        let (plaintext, tag) = data.split_at_mut(data.len() - tag_len);
        let tag = aes_gcm::aead::Tag::<Cipher>::try_from(&*tag).unwrap();
        <Cipher as KeyInit>::new(write.get_key().unwrap())
            .decrypt_inout_detached(
                &write.get_nonce().unwrap(),
                header,
                (&mut *plaintext).into(),
                &tag,
            )
            .unwrap();
        (result, transcript_hash, plaintext.to_vec())
    }

    /// The signature in the plaintext of a client `CertificateVerify` record, after checking its
    /// framing and its `ecdsa_secp256r1_sha256` scheme.
    fn certificate_verify_signature(plaintext: &[u8]) -> &[u8] {
        let (content_type, message) = plaintext.split_last().unwrap();
        assert_eq!(*content_type, ContentType::Handshake as u8);
        assert_eq!(message[0], HandshakeType::CertificateVerify as u8);
        assert_eq!(
            u32::from_be_bytes([0, message[1], message[2], message[3]]) as usize,
            message.len() - 4
        );
        assert_eq!(
            u16::from_be_bytes([message[4], message[5]]),
            SignatureScheme::EcdsaSecp256r1Sha256.as_u16()
        );
        let signature = &message[8..];
        assert_eq!(
            usize::from(u16::from_be_bytes([message[6], message[7]])),
            signature.len()
        );
        signature
    }

    /// Checks `signature` over the `CertificateVerify` content of `transcript_hash` with the
    /// public key of the client key, as the server does (RFC 8446 section 4.4.3).
    fn verify_client_signature(transcript_hash: &[u8], signature: &[u8]) {
        use signature::Verifier;

        let secret_key = p256::SecretKey::from_sec1_der(&client_key_der()).unwrap();
        let signing_key = p256::ecdsa::SigningKey::from(&secret_key);
        let signature = p256::ecdsa::DerSignature::try_from(signature).unwrap();
        let content = certificate_verify_content(transcript_hash).unwrap();
        signing_key
            .verifying_key()
            .verify(&content, &signature)
            .unwrap();
    }

    #[test]
    fn the_unsecure_provider_signs_one_transcript_hedged() {
        let key = client_key_der();
        let mut provider = UnsecureProvider::new::<Suite>(UnwrapErr(SysRng)).with_priv_key(&key);
        let (first, first_hash, first_record) = certificate_verify_record(&mut provider);
        let (second, second_hash, second_record) = certificate_verify_record(&mut provider);
        assert!(matches!(first, Ok(State::ClientFinished)), "{first:?}");
        assert!(matches!(second, Ok(State::ClientFinished)), "{second:?}");
        assert_eq!(first_hash, second_hash);

        let first_signature = certificate_verify_signature(&first_record);
        let second_signature = certificate_verify_signature(&second_record);
        assert_ne!(first_signature, second_signature);
        verify_client_signature(&first_hash, first_signature);
        verify_client_signature(&second_hash, second_signature);
    }

    #[test]
    fn a_deterministic_signer_signs_one_transcript_alike() {
        let secret_key = p256::SecretKey::from_sec1_der(&client_key_der()).unwrap();
        let mut provider =
            SignWith(|| crate::SignerRef(p256::ecdsa::SigningKey::from(&secret_key)));
        let (first, hash, first_record) = certificate_verify_record(&mut provider);
        let (second, _, second_record) = certificate_verify_record(&mut provider);
        assert!(matches!(first, Ok(State::ClientFinished)), "{first:?}");
        assert!(matches!(second, Ok(State::ClientFinished)), "{second:?}");

        let signature = certificate_verify_signature(&first_record);
        assert_eq!(signature, certificate_verify_signature(&second_record));
        verify_client_signature(&hash, signature);
    }

    #[test]
    fn a_failing_signer_fails_the_handshake_without_panicking() {
        let (result, _, plaintext) =
            certificate_verify_record(&mut SignWith(|| crate::config::NoSign));
        assert!(matches!(result, Err(TlsError::CryptoError)), "{result:?}");
        assert_eq!(plaintext.last(), Some(&(ContentType::Alert as u8)));
    }

    #[test]
    fn a_failing_rng_fails_the_hedged_signature_without_panicking() {
        let secret_key = p256::SecretKey::from_sec1_der(&client_key_der()).unwrap();
        let mut provider = SignWith(|| {
            crate::RandomizedSignerRef::new(p256::ecdsa::SigningKey::from(&secret_key), FailingRng)
        });
        let (result, _, plaintext) = certificate_verify_record(&mut provider);
        assert!(matches!(result, Err(TlsError::CryptoError)), "{result:?}");
        assert_eq!(plaintext.last(), Some(&(ContentType::Alert as u8)));
    }
}
