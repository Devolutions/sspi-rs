pub(crate) mod as_exchange;
mod cache;
mod extractors;
mod generators;

use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use cache::AuthenticatorCacheRecord;
pub use cache::AuthenticatorsCache;
use picky::oids;
use picky_asn1::restricted_string::IA5String;
use picky_asn1::wrapper::{
    Asn1SequenceOf, ExplicitContextTag0, ExplicitContextTag1, ExplicitContextTag2, ExplicitContextTag3, IntegerAsn1,
    Optional,
};
use picky_krb::constants::gss_api::{AP_REP_TOKEN_ID, AP_REQ_TOKEN_ID, TGT_REP_TOKEN_ID, TGT_REQ_TOKEN_ID};
use picky_krb::constants::types::NT_SRV_INST;
use picky_krb::crypto::CipherSuite;
use picky_krb::data_types::{AuthenticatorInner, KerberosStringAsn1, PrincipalName};
use picky_krb::gss_api::MechTypeList;
use picky_krb::messages::{ApRep, ApReq, TgtReq};
use rand::rngs::{StdRng, SysRng};
use rand_core::{Rng as _, SeedableRng as _};
use serde::Deserialize;
use time::OffsetDateTime;

use self::extractors::{decrypt_ap_req_authenticator, decrypt_ap_req_ticket};
use self::generators::generate_ap_rep;
use crate::builders::FilledAcceptSecurityContext;
use crate::generator::YieldPointLocal;
use crate::kerberos::DEFAULT_ENCRYPTION_TYPE;
use crate::kerberos::client::extractors::{decrypt_ap_rep, extract_seq_number_from_ap_rep};
use crate::kerberos::flags::ApOptions;
use crate::kerberos::messages::{decode_krb_message, generate_krb_message};
use crate::kerberos::server::as_exchange::request_tgt;
use crate::kerberos::server::extractors::client_upn;
use crate::kerberos::server::generators::generate_tgt_rep;
use crate::{
    AcceptSecurityContextResult, BufferType, CredentialsBuffers, Error, ErrorKind, Kerberos, KerberosState, Result,
    Secret, SecurityBuffer, SecurityStatus, ServerRequestFlags, ServerResponseFlags, SspiImpl, Username,
};

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum KerberosServerState {
    TgtExchange,
    Preauthentication,
    ApExchange,
}

/// Additional properties that are needed only for server-side Kerberos.
#[derive(Debug, Clone)]
pub struct ServerProperties {
    /// Supported mech types sent by the client in the first incoming message.
    /// We user them for checksum calculation during MIC token generation.
    pub mech_types: MechTypeList,
    /// Maximum allowed time difference between client and server clocks.
    /// It is recommended to set this value not greater then a few minutes.
    pub max_time_skew: Duration,
    /// Key that is used for TGS tickets decryption.
    /// It should be provided by the user during regular Kerberos auth. Or
    /// it will be established during AS exchange in the case of Kerberos U2U auth.
    pub ticket_decryption_key: Option<Secret<Vec<u8>>>,
    /// Name of the Kerberos service.
    pub service_name: PrincipalName,
    /// Additional service principals this acceptor will honor, each paired
    /// with its own ticket-decryption key. A single keytab routinely holds
    /// keys for several host SPNs (e.g. `kafka/localhost` and
    /// `kafka/host.docker.internal`); the acceptor must validate an incoming
    /// AP-REQ against whichever SPN the client's ticket actually names — not
    /// just one pinned name — matching the behavior of MIT/Heimdal GSSAPI
    /// acceptors that key off the whole keytab.
    pub additional_service_keys: Vec<(PrincipalName, Secret<Vec<u8>>)>,
    /// User credentials on whose behalf the TGT ticket will be requested.
    ///
    /// Keytab credentials let a keytab-only acceptor complete Kerberos user-to-user authentication.
    ///
    /// Create the `Negotiate` server with `Negotiate::new_server_authorizing_externally` so that it does not look
    /// for the client among identities, and authorize the principal from `Negotiate::client_principal`, which keeps
    /// every name component and the realm.
    /// A server with an identities list matches the client against a name that keeps only the first component,
    /// and only when a `mechListMIC` is exchanged.
    ///
    /// A service principal must be given in the down-level form (`TERMSRV/host`), a UPN is sent as an `NT-ENTERPRISE` name.
    /// The key should be the AES256 key of the principal, the first encryption type the AS-REQ offers.
    pub user: Option<CredentialsBuffers>,
    /// Username of the authenticated client.
    ///
    /// This field should be set by the Kerberos implementation after successful log on.
    pub client: Option<Username>,
    /// Authenticators cache.
    ///
    /// [Receipt of KRB_AP_REQ Message](https://www.rfc-editor.org/rfc/rfc4120#section-3.2.3):
    ///
    /// > The server MUST utilize a replay cache to remember any authenticator presented within the allowable clock skew.
    /// > The replay cache will store at least the server name, along with the client name, time,
    /// > and microsecond fields from the recently-seen authenticators, and if a matching tuple is found,
    /// > the error is returned.
    ///
    /// Share the cache between all the contexts of the same service: a replay is only detected by the cache
    /// that has seen the original authenticator.
    pub authenticators_cache: Arc<Mutex<AuthenticatorsCache>>,
}

impl ServerProperties {
    /// Creates a new instance of [ServerProperties].
    pub fn new(
        sname: &[&str],
        user: Option<CredentialsBuffers>,
        max_time_skew: Duration,
        ticket_decryption_key: Option<Secret<Vec<u8>>>,
        authenticators_cache: Arc<Mutex<AuthenticatorsCache>>,
    ) -> Result<Self> {
        let service_names = sname
            .iter()
            .map(|sname| Ok(KerberosStringAsn1::from(IA5String::from_string((*sname).to_owned())?)))
            .collect::<Result<Vec<_>>>()?;

        Ok(Self {
            mech_types: MechTypeList::from(Vec::new()),
            max_time_skew,
            ticket_decryption_key,
            service_name: PrincipalName {
                name_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![NT_SRV_INST])),
                name_string: ExplicitContextTag1::from(Asn1SequenceOf::from(service_names)),
            },
            additional_service_keys: Vec::new(),
            user,
            client: None,
            authenticators_cache,
        })
    }

    /// Register an additional service principal (by name components, without
    /// realm) and its ticket-decryption key. The acceptor will accept an
    /// AP-REQ whose ticket names this principal in addition to the primary
    /// [`service_name`](Self::service_name).
    pub fn add_service_key(&mut self, sname: &[&str], key: Secret<Vec<u8>>) -> Result<()> {
        let service_names = sname
            .iter()
            .map(|sname| Ok(KerberosStringAsn1::from(IA5String::from_string((*sname).to_owned())?)))
            .collect::<Result<Vec<_>>>()?;
        let principal = PrincipalName {
            name_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![NT_SRV_INST])),
            name_string: ExplicitContextTag1::from(Asn1SequenceOf::from(service_names)),
        };
        self.additional_service_keys.push((principal, key));
        Ok(())
    }

    /// Resolve the ticket-decryption key for an incoming AP-REQ whose ticket
    /// names `ticket_sname`. Matches the requested service principal against
    /// the primary [`service_name`](Self::service_name) and any
    /// [`additional_service_keys`](Self::additional_service_keys), comparing
    /// name components only (ignoring the PrincipalName `name-type`, per
    /// RFC 4120 §6.2). Returns the matching key, or `None` if no configured
    /// service principal matches.
    pub fn ticket_decryption_key_for(&self, ticket_sname: &PrincipalName) -> Option<&Secret<Vec<u8>>> {
        if self.service_name.name_string.0 == ticket_sname.name_string.0
            && let Some(key) = self.ticket_decryption_key.as_ref()
        {
            return Some(key);
        }
        self.additional_service_keys
            .iter()
            .find(|(spn, _)| spn.name_string.0 == ticket_sname.name_string.0)
            .map(|(_, key)| key)
    }
}

/// Message version of the tickets, authenticators and AP-REQ messages (`pvno`, `tkt-vno`, `authenticator-vno`).
const KERBEROS_V5: u8 = 5;
/// `msg-type` of the `KRB_AP_REQ` message.
const KRB_AP_REQ_MSG_TYPE: u8 = 14;
/// The `INVALID` bit of the ticket flags. Bit 7 is the last bit of the first flags octet.
const TICKET_FLAG_INVALID: u8 = 0b0000_0001;

/// Returns an error if the INTEGER does not have the expected value.
fn expect_integer(value: &IntegerAsn1, expected: u8, description: &str) -> Result<()> {
    let bytes = value.as_unsigned_bytes_be();
    let start = bytes.iter().position(|byte| *byte != 0).unwrap_or(bytes.len());

    if bytes[start..] != [expected] {
        return Err(Error::new(
            ErrorKind::InvalidToken,
            format!("unsupported {description}: expected {expected}"),
        ));
    }

    Ok(())
}

/// The client principal authenticated by a Kerberos acceptor, as named by the ticket.
///
/// The [`Username`] from [`Sspi::query_context_names`](crate::Sspi::query_context_names) can lose part of the
/// principal: it keeps the first name component and lowercases the realm. Consumers that authorize on the principal,
/// or map it with case-sensitive rules such as MIT Kerberos' `auth_to_local`, need the original.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientPrincipal {
    components: Vec<String>,
    realm: String,
}

impl ClientPrincipal {
    pub(crate) fn from_ticket(cname: &PrincipalName, crealm: &KerberosStringAsn1) -> Self {
        Self {
            components: cname
                .name_string
                .0
                .0
                .iter()
                .map(|component| component.to_string())
                .collect(),
            realm: crealm.0.to_string(),
        }
    }

    /// The name components in order: `["alice", "admin"]` for `alice/admin@EXAMPLE.COM`.
    pub fn components(&self) -> &[String] {
        &self.components
    }

    /// The realm, in the ticket's case.
    pub fn realm(&self) -> &str {
        &self.realm
    }
}

/// `TGT-REQ` with the optional `server-realm`, which `picky_krb::messages::TgtReq` does not model.
///
/// ```not_rust
/// TGT-REQ ::= SEQUENCE {
///     pvno[0]         INTEGER,
///     msg-type[1]     INTEGER,
///     server-name[2]  PrincipalName OPTIONAL,
///     server-realm[3] Realm OPTIONAL
/// }
/// ```
///
/// Windows sends the realm. As in `TgtReq`, the server name is required here.
/// `decode_krb_message` rejects trailing bytes, so decoding it as a bare `TgtReq` fails with `InvalidData`.
/// The realm is ignored, the service name identifies the target.
///
/// The structure is defined in [draft-ietf-krb-wg-user2user][user2user].
///
/// [user2user]: https://datatracker.ietf.org/doc/html/draft-swift-win2k-krb-user2user-01
#[derive(Deserialize)]
#[cfg_attr(test, derive(Debug, PartialEq, serde::Serialize))]
struct TgtReqWithRealm {
    pvno: ExplicitContextTag0<IntegerAsn1>,
    msg_type: ExplicitContextTag1<IntegerAsn1>,
    server_name: ExplicitContextTag2<PrincipalName>,
    #[serde(default)]
    _server_realm: Optional<Option<ExplicitContextTag3<KerberosStringAsn1>>>,
}

impl From<TgtReqWithRealm> for TgtReq {
    fn from(tgt_req: TgtReqWithRealm) -> Self {
        Self {
            pvno: tgt_req.pvno,
            msg_type: tgt_req.msg_type,
            server_name: tgt_req.server_name,
        }
    }
}

/// Performs one authentication step.
///
/// The user should call this function until it returns `SecurityStatus::Ok`.
pub async fn accept_security_context(
    server: &mut Kerberos,
    yield_point: &mut YieldPointLocal,
    builder: FilledAcceptSecurityContext<'_, <Kerberos as SspiImpl>::CredentialsHandle>,
) -> Result<AcceptSecurityContextResult> {
    let mut state = match &server.state {
        KerberosState::Server(state) => *state,
        KerberosState::Failed => {
            return Err(Error::new(
                ErrorKind::InvalidHandle,
                "Kerberos server is in failed state",
            ));
        }
        wrong_state @ (KerberosState::Client(_) | KerberosState::Final) => {
            return Err(Error::new(
                ErrorKind::OutOfSequence,
                format!("got wrong Kerberos state: {:?}", wrong_state),
            ));
        }
    };

    let input = builder
        .input
        .as_ref()
        .ok_or_else(|| Error::new(ErrorKind::InvalidToken, "input buffers must be specified"))?;
    let input_token = SecurityBuffer::find_buffer(input, BufferType::Token)?;

    if state == KerberosServerState::TgtExchange {
        if let Ok(tgt_req) = if builder.context_requirements.contains(ServerRequestFlags::USE_DCE_STYLE) {
            picky_asn1_der::from_bytes::<TgtReqWithRealm>(&input_token.buffer).map_err(Error::from)
        } else {
            decode_krb_message::<TgtReqWithRealm>(&input_token.buffer, TGT_REQ_TOKEN_ID)
        }
        .map(TgtReq::from)
        {
            // The first token is TGT_REQ. It means that the client wants to perform Kerberos U2U.

            if !builder
                .context_requirements
                .contains(ServerRequestFlags::USE_SESSION_KEY)
            {
                warn!(
                    "KRB5 U2U has been negotiated (requested by the client) but the USE_SESSION_KEY flag is not set."
                );
            }

            server.krb5_user_to_user = true;

            let credentials = server
                .server
                .as_ref()
                .ok_or_else(|| Error::new(ErrorKind::IncompleteCredentials, "Kerberos server configuration not present"))?
                .user
                .as_ref()
                .ok_or_else(|| Error::new(ErrorKind::IncompleteCredentials, "KRB5 U2U has been negotiated (requested by the client) but the user credentials are not preset in Kerberos server configuration"))?
                .clone();

            let tgt_rep = generate_tgt_rep(request_tgt(server, &credentials, &tgt_req, yield_point).await?);

            let mech_id = if server.krb5_user_to_user {
                oids::krb5_user_to_user()
            } else {
                oids::krb5()
            };

            let encoded_tgt_rep = if builder.context_requirements.contains(ServerRequestFlags::USE_DCE_STYLE) {
                picky_asn1_der::to_vec(&tgt_rep)?
            } else {
                generate_krb_message(mech_id, TGT_REP_TOKEN_ID, tgt_rep)?
            };

            let output_token = SecurityBuffer::find_buffer_mut(builder.output, BufferType::Token)?;
            output_token.buffer = encoded_tgt_rep;

            server.state = KerberosState::Server(KerberosServerState::Preauthentication);

            return Ok(AcceptSecurityContextResult {
                status: SecurityStatus::ContinueNeeded,
                flags: ServerResponseFlags::empty(),
                expiry: None,
            });
        } else if let Ok(_ap_req) = if builder.context_requirements.contains(ServerRequestFlags::USE_DCE_STYLE) {
            picky_asn1_der::from_bytes::<ApReq>(&input_token.buffer).map_err(Error::from)
        } else {
            decode_krb_message::<ApReq>(&input_token.buffer, AP_REQ_TOKEN_ID)
        } {
            // The client may send ApReq instead of TgtReq in the first message.
            // It means that the client wants to perform regular Kerberos without U2U.
            // In that case, we just move Kerberos state to the next one and process further.
            state = KerberosServerState::Preauthentication;
        } else {
            return Err(Error::new(
                ErrorKind::InvalidToken,
                "invalid Kerberos token: expected TgtReq or ApReq",
            ));
        }
    }

    let status = match state {
        KerberosServerState::Preauthentication => {
            let ap_req = if builder.context_requirements.contains(ServerRequestFlags::USE_DCE_STYLE) {
                picky_asn1_der::from_bytes::<ApReq>(&input_token.buffer)?
            } else {
                decode_krb_message::<ApReq>(&input_token.buffer, AP_REQ_TOKEN_ID)?
            };

            // [3.2.3.  Receipt of KRB_AP_REQ Message](https://www.rfc-editor.org/rfc/rfc4120#section-3.2.3)
            // If the message type is not KRB_AP_REQ, the server returns the KRB_AP_ERR_MSG_TYPE error.
            // If the version numbers of the message or of the ticket are not 5, it returns KRB_AP_ERR_BADVERSION.
            expect_integer(&ap_req.0.msg_type.0, KRB_AP_REQ_MSG_TYPE, "AP-REQ message type")?;
            expect_integer(&ap_req.0.pvno.0, KERBEROS_V5, "AP-REQ version")?;
            expect_integer(&ap_req.0.ticket.0.0.tkt_vno.0, KERBEROS_V5, "ticket version")?;

            let server_data = server.server.as_ref().ok_or_else(|| {
                Error::new(
                    ErrorKind::InvalidHandle,
                    "Kerberos server properties are not initialized",
                )
            })?;

            let ticket_service_name = &ap_req.0.ticket.0.0.sname.0;
            // Match the service principal by its name components only, ignoring
            // the PrincipalName `name-type`. RFC 4120 §6.2 treats the name-type
            // as a hint about how to interpret the components, not as part of
            // the principal's identity, and acceptors (MIT, Heimdal) key off
            // the components. Stock Kafka GSSAPI clients build the server
            // principal as NT-UNKNOWN/NT-PRINCIPAL while a `kafka/host` keytab
            // entry is NT-SRV-INST, so a name-type-sensitive comparison would
            // spuriously reject otherwise-valid tickets.
            //
            // A keytab may carry keys for several host SPNs; accept whichever
            // one the ticket actually names and decrypt with its key.
            let ticket_decryption_key =
                server_data
                    .ticket_decryption_key_for(ticket_service_name)
                    .ok_or_else(|| {
                        Error::new(
                            ErrorKind::InvalidToken,
                            format!(
                                "invalid ticket service name ({:?}): no matching service key configured (primary {:?})",
                                ticket_service_name, server_data.service_name
                            ),
                        )
                    })?;

            let ticket_enc_part = decrypt_ap_req_ticket(ticket_decryption_key, &ap_req)?;
            let session_key = Secret::new(ticket_enc_part.0.key.0.key_value.0.0.clone());

            // [3.2.3.  Receipt of KRB_AP_REQ Message](https://www.rfc-editor.org/rfc/rfc4120#section-3.2.3)
            // If the INVALID flag is set in the ticket, the problem is reported as the KRB_AP_ERR_TKT_NYV error.
            // The ticket has to be validated by the KDC first.
            if ticket_enc_part
                .0
                .flags
                .0
                .0
                .as_bytes()
                .get(1)
                .is_some_and(|flags| flags & TICKET_FLAG_INVALID != 0)
            {
                return Err(Error::new(
                    ErrorKind::InvalidToken,
                    "the ticket is not valid yet: the INVALID flag is set",
                ));
            }

            let AuthenticatorInner {
                authenticator_vno,
                crealm,
                cname,
                cksum: _,
                cusec,
                ctime,
                subkey,
                seq_number,
                authorization_data: _,
            } = decrypt_ap_req_authenticator(&session_key, &ap_req)?.0;

            expect_integer(&authenticator_vno.0, KERBEROS_V5, "authenticator version")?;

            // RFC 4121 §4.2: if the initiator places a subkey in its
            // Authenticator and the acceptor returns no subkey of its own
            // (i.e. no mutual-auth AP-REP), that initiator subkey — not the
            // ticket session key — becomes the key for per-message (wrap/MIC)
            // tokens. Stock Java/Kafka GSSAPI clients always send an
            // Authenticator subkey, so dropping it makes the security-layer
            // wrap fail the client's checksum. Capture it here; the non-mutual
            // branch below installs it as the sub-session key.
            let authenticator_subkey: Option<Secret<Vec<u8>>> =
                subkey.0.as_ref().map(|key| Secret::new(key.0.key_value.0.0.clone()));

            // The ticket, not the acceptor configuration, tells the encryption type of the session key.
            // The AP-REP and the acceptor subkey follow it, and a subkey of the initiator brings its own type.
            // The per-message tokens are protected with that type.
            let session_key_type = CipherSuite::try_from(ticket_enc_part.0.key.0.key_type.0.0.as_slice())?;
            let authenticator_subkey_type = subkey
                .0
                .as_ref()
                .map(|key| CipherSuite::try_from(key.0.key_type.0.0.as_slice()))
                .transpose()?;

            // The initiator's Authenticator sequence number. Without a mutual-
            // auth AP-REP to carry an acceptor sequence number, GSS initiators
            // (e.g. Java) initialise the *expected* acceptor sequence to their
            // own initiator value, so the acceptor's per-message tokens must be
            // numbered from it or the initiator rejects them as "gap" tokens.
            let authenticator_seq_number: Option<u32> = seq_number.0.as_ref().map(|seq| {
                let seq_number_bytes = &seq.0.0;
                // IntegerAsn1 is big-endian and may carry a leading 0x00 sign
                // byte; take the low 4 octets.
                let mut buf = [0u8; 4];
                let start = seq_number_bytes.len().saturating_sub(4);
                let slice = &seq_number_bytes[start..];
                buf[4 - slice.len()..].copy_from_slice(slice);
                u32::from_be_bytes(buf)
            });

            if let Some(seq) = authenticator_seq_number {
                server.remote_seq_number = seq;
            }

            // [3.2.3.  Receipt of KRB_AP_REQ Message](https://www.rfc-editor.org/rfc/rfc4120#section-3.2.3)
            // The name and realm of the client from the ticket are compared against the same fields in the authenticator.
            if ticket_enc_part.0.crealm.0 != crealm.0 || ticket_enc_part.0.cname != cname.0 {
                return Err(Error::new(
                    ErrorKind::InvalidToken,
                    "the name and realm of the client in ticket and authenticator do not match",
                ));
            }

            let now = OffsetDateTime::now_utc();
            let client_time = OffsetDateTime::try_from(ctime.0.0.clone())
                .map_err(|err| Error::new(ErrorKind::InvalidToken, format!("client time is not valid: {err:?}")))?;
            let max_time_skew = server_data.max_time_skew;

            if (now - client_time).abs() > max_time_skew {
                return Err(Error::new(
                    ErrorKind::TimeSkew,
                    "invalid authenticator ctime: time skew is too big",
                ));
            }

            let ticket_start_time = ticket_enc_part
                .0
                .starttime
                .0
                .map(|start_time| start_time.0)
                // [5.3.  Tickets](https://www.rfc-editor.org/rfc/rfc4120#section-5.3)
                // If the starttime field is absent from the ticket, then the authtime field SHOULD be used in its place to determine
                // the life of the ticket.
                .unwrap_or_else(|| ticket_enc_part.0.auth_time.0)
                .0;
            let ticket_start_time = OffsetDateTime::try_from(ticket_start_time).map_err(|err| {
                Error::new(
                    ErrorKind::InvalidToken,
                    format!("ticket end time is not valid: {err:?}"),
                )
            })?;
            if ticket_start_time > now + max_time_skew {
                return Err(Error::new(
                    ErrorKind::InvalidToken,
                    "ticket not yet valid: ticket start time is greater than current time + max time skew",
                ));
            }

            let ticket_end_time = OffsetDateTime::try_from(ticket_enc_part.0.endtime.0.0).map_err(|err| {
                Error::new(
                    ErrorKind::InvalidToken,
                    format!("ticket end time is not valid: {err:?}"),
                )
            })?;
            if now > ticket_end_time + max_time_skew {
                return Err(Error::new(
                    ErrorKind::InvalidToken,
                    "ticket is expired: current time is greater than ticket end time + max time skew",
                ));
            }

            let server_data = server.server.as_mut().ok_or_else(|| {
                Error::new(
                    ErrorKind::InvalidHandle,
                    "Kerberos server properties are not initialized",
                )
            })?;

            // An authenticator outside of the allowed clock skew is rejected by the time check above,
            // so it does not have to be remembered. Forget it, or the cache grows with every request.
            let cache_record = AuthenticatorCacheRecord {
                cname: cname.0.clone(),
                sname: ticket_service_name.clone(),
                ctime: ctime.0.clone(),
                microseconds: cusec.0.clone(),
            };
            // The cache holds plain records, so it stays consistent even if another thread panicked while holding the lock.
            let mut authenticators_cache = server_data
                .authenticators_cache
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            authenticators_cache.retain(|record| {
                OffsetDateTime::try_from(record.ctime.0.clone())
                    .is_ok_and(|record_time| (now - record_time).abs() <= max_time_skew)
            });
            if !authenticators_cache.insert(cache_record) {
                return Err(Error::new(
                    ErrorKind::InvalidToken,
                    "ApReq Authenticator replay detected",
                ));
            }
            drop(authenticators_cache);

            debug!("ApReq Ticket and Authenticator are valid!");

            server_data.client = Some(client_upn(&cname.0, &crealm.0)?);
            // The ticket was issued by the KDC. The authenticator was written by the client.
            server.client_principal = Some(ClientPrincipal::from_ticket(
                &ticket_enc_part.0.cname.0,
                &ticket_enc_part.0.crealm.0,
            ));

            let ap_options_bytes = ap_req.0.ap_options.0.0.as_bytes();
            // [5.5.1.  KRB_AP_REQ Definition](https://www.rfc-editor.org/rfc/rfc4120#section-5.5.1)
            // The `ap-options` field has 32 bits or 4 bytes long. But it is encoded as BitStringAsn1, so the first byte
            // indicates the number of bits used. Thus, the overall number of expected bytes is 1 + 4 = 5.
            if ap_options_bytes.len() != 1 + 4 {
                return Err(Error::new(
                    ErrorKind::InvalidToken,
                    format!(
                        "invalid ApReq ap-options: invalid data length: expected 5 bytes but got {}",
                        ap_options_bytes.len()
                    ),
                ));
            }
            let ap_options =
                u32::from_be_bytes(ap_options_bytes[1..].try_into().map_err(|err| {
                    Error::new(ErrorKind::InvalidToken, format!("invalid ApReq ap-options: {err:?}"))
                })?);
            let ap_options = ApOptions::from_bits(ap_options)
                .ok_or_else(|| Error::new(ErrorKind::InvalidToken, "invalid ApReq ap-options"))?;

            // [3.2.4.  Generation of a KRB_AP_REP Message](https://www.rfc-editor.org/rfc/rfc4120#section-3.2.3)
            // ...the server need not explicitly reply to the KRB_AP_REQ. However, if mutual authentication is being performed,
            // the KRB_AP_REQ message will have MUTUAL-REQUIRED set in its ap-options field, and a KRB_AP_REP message
            // is required in response.
            let status = if ap_options.contains(ApOptions::MUTUAL_REQUIRED) {
                server.encryption_params.encryption_type = Some(session_key_type);
                let key_size = server
                    .encryption_params
                    .encryption_type
                    .as_ref()
                    .unwrap_or(&DEFAULT_ENCRYPTION_TYPE)
                    .cipher()
                    .key_size();
                let mut sub_session_key = vec![0; key_size];

                let mut rand = StdRng::try_from_rng(&mut SysRng)?;
                rand.fill_bytes(&mut sub_session_key);
                server.encryption_params.sub_session_key = Some(sub_session_key.into());

                // [3.2.4.  Generation of a KRB_AP_REP Message](https://www.rfc-editor.org/rfc/rfc4120#section-3.2.3)
                // A subkey MAY be included if the server desires to negotiate a different subkey.
                // The KRB_AP_REP message is encrypted in the session key extracted from the ticket.
                let ap_rep = generate_ap_rep(
                    &session_key,
                    ctime.0,
                    cusec.0,
                    server.seq_number.wrapping_add(1),
                    &server.encryption_params,
                )?;

                let mech_id = if server.krb5_user_to_user {
                    oids::krb5_user_to_user()
                } else {
                    oids::krb5()
                };

                let (status, encoded_ap_rep) =
                    if builder.context_requirements.contains(ServerRequestFlags::USE_DCE_STYLE) {
                        let encoded_ap_rep = picky_asn1_der::to_vec(&ap_rep)?;
                        server.state = KerberosState::Server(KerberosServerState::ApExchange);

                        (SecurityStatus::ContinueNeeded, encoded_ap_rep)
                    } else {
                        let encoded_ap_rep = generate_krb_message(mech_id, AP_REP_TOKEN_ID, ap_rep)?;
                        server.state = KerberosState::Final;

                        (SecurityStatus::Ok, encoded_ap_rep)
                    };

                let output_token = SecurityBuffer::find_buffer_mut(builder.output, BufferType::Token)?;
                output_token.buffer = encoded_ap_rep;

                status
            } else {
                // No mutual auth requested: the server emits no AP-REP, but the
                // GSS context is nonetheless established from a valid AP-REQ
                // (RFC 4120 §3.2.4 — MUTUAL-REQUIRED only governs whether an
                // AP-REP is returned, not whether the context is usable). Move
                // to Final so subsequent wrap/unwrap (e.g. the SASL GSSAPI
                // security-layer negotiation) succeed instead of erroring with
                // "context is not established".
                //
                // Since we return no acceptor subkey, per-message tokens use the
                // initiator's Authenticator subkey if it provided one (RFC 4121
                // §4.2), falling back to the ticket session key otherwise.
                server.encryption_params.encryption_type = Some(authenticator_subkey_type.unwrap_or(session_key_type));
                if let Some(subkey) = authenticator_subkey {
                    server.encryption_params.sub_session_key = Some(subkey);
                }

                // Number our outgoing per-message tokens from the initiator's
                // Authenticator sequence number. With no AP-REP to carry an
                // acceptor sequence, GSS initiators set their *expected*
                // acceptor sequence equal to their own initiator value, so the
                // first acceptor wrap token must use that number or the
                // initiator rejects it as a "gap" token. `next_seq_number()`
                // pre-increments, so seed one below.
                if let Some(seq) = authenticator_seq_number {
                    server.seq_number = seq.wrapping_sub(1);
                }
                server.state = KerberosState::Final;

                SecurityStatus::Ok
            };

            server.encryption_params.session_key = Some(session_key);

            status
        }
        KerberosServerState::ApExchange => {
            if !builder.context_requirements.contains(ServerRequestFlags::USE_DCE_STYLE) {
                return Err(Error::new(
                    ErrorKind::OutOfSequence,
                    "USE_DCE_STYLE flag must be set in context requirements",
                ));
            }

            let ap_rep = picky_asn1_der::from_bytes::<ApRep>(&input_token.buffer)?;

            let session_key = server
                .encryption_params
                .session_key
                .as_ref()
                .ok_or_else(|| Error::new(ErrorKind::InternalError, "session key is not set"))?;
            let ap_rep_enc_part = decrypt_ap_rep(&ap_rep, session_key, &server.encryption_params)?;
            let seq_number = extract_seq_number_from_ap_rep(&ap_rep_enc_part)?;

            let expected_seq_number = server.seq_number.wrapping_add(1);
            if seq_number != expected_seq_number {
                return Err(Error::new(
                    ErrorKind::InvalidToken,
                    format!(
                        "invalid client ApRep sequence number: expected {expected_seq_number} but got {seq_number}",
                    ),
                ));
            }

            server.state = KerberosState::Final;

            SecurityStatus::Ok
        }
        KerberosServerState::TgtExchange => unreachable!("TgtExchange state is handled above"),
    };

    Ok(AcceptSecurityContextResult {
        status,
        flags: ServerResponseFlags::empty(),
        expiry: None,
    })
}

#[cfg(test)]
mod tests {
    use picky_krb::constants::gss_api::TGT_REQ_TOKEN_ID;
    use picky_krb::constants::types::{NT_PRINCIPAL, NT_SRV_HST};
    use picky_krb::crypto::CipherSuite;
    use picky_krb::messages::AsReq;
    use url::Url;

    use super::*;
    use crate::generator::{GeneratorState, NetworkRequest};
    use crate::kerberos::messages::{decode_krb_message, generate_krb_message};
    use crate::kerberos::test_data::{TGT_REQ_TOKEN_WITH_REALM, fake_server};
    use crate::{
        AuthIdentity, Credentials, DataRepresentation, KdcResolution, KeytabIdentity, Sspi, SspiImpl, Username,
    };

    fn password_user() -> CredentialsBuffers {
        CredentialsBuffers::try_from(Credentials::AuthIdentity(AuthIdentity {
            username: Username::new_down_level_logon_name("user", "EXAMPLE").unwrap(),
            password: "password".to_owned().into(),
        }))
        .unwrap()
    }

    fn tgt_req(name_type: u8, host: &str, realm: Option<&str>) -> TgtReqWithRealm {
        let component = |value: &str| KerberosStringAsn1::from(IA5String::from_string(value.to_owned()).unwrap());

        TgtReqWithRealm {
            pvno: ExplicitContextTag0::from(IntegerAsn1::from(vec![5])),
            msg_type: ExplicitContextTag1::from(IntegerAsn1::from(vec![16])),
            server_name: ExplicitContextTag2::from(PrincipalName {
                name_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![name_type])),
                name_string: ExplicitContextTag1::from(Asn1SequenceOf::from(vec![
                    component("TERMSRV"),
                    component(host),
                ])),
            }),
            _server_realm: Optional::from(realm.map(|realm| ExplicitContextTag3::from(component(realm)))),
        }
    }

    /// Feeds `token` to a U2U acceptor as its first token.
    ///
    /// Returns the request for the KDC when the acceptor got as far as the AS exchange for its own TGT.
    fn accept_first_token(
        user: CredentialsBuffers,
        token: &[u8],
        context_requirements: ServerRequestFlags,
    ) -> Result<NetworkRequest> {
        let mut kerberos = fake_server();
        kerberos.state = KerberosState::Server(KerberosServerState::TgtExchange);
        kerberos.config.kdc_resolution = KdcResolution::KdcUrl(Some(Url::parse("tcp://192.168.1.103:88").unwrap()));
        kerberos.server.as_mut().unwrap().user = Some(user);

        let mut credentials_handle: Option<CredentialsBuffers> = None;
        let mut input = [SecurityBuffer::new(token.to_vec(), BufferType::Token)];
        let mut output = [SecurityBuffer::new(Vec::new(), BufferType::Token)];
        let builder = kerberos
            .accept_security_context()
            .with_credentials_handle(&mut credentials_handle)
            .with_context_requirements(context_requirements)
            .with_target_data_representation(DataRepresentation::Native)
            .with_input(&mut input)
            .with_output(&mut output);
        let mut generator = SspiImpl::accept_security_context_impl(&mut kerberos, builder)?;

        match generator.start() {
            GeneratorState::Suspended(request) => Ok(request),
            GeneratorState::Completed(Err(error)) => Err(error),
            GeneratorState::Completed(Ok(_)) => Err(Error::new(ErrorKind::InternalError, "the exchange completed")),
        }
    }

    #[test]
    fn a_tgt_req_with_a_server_realm_is_accepted() {
        accept_first_token(
            password_user(),
            TGT_REQ_TOKEN_WITH_REALM,
            ServerRequestFlags::USE_SESSION_KEY,
        )
        .unwrap();
    }

    #[test]
    fn a_tgt_req_without_a_server_realm_is_accepted() {
        let token = generate_krb_message(
            oids::krb5_user_to_user(),
            TGT_REQ_TOKEN_ID,
            tgt_req(NT_SRV_INST, "VM1.example.com", None),
        )
        .unwrap();

        accept_first_token(password_user(), &token, ServerRequestFlags::USE_SESSION_KEY).unwrap();
    }

    #[test]
    fn a_dce_style_tgt_req_with_a_server_realm_is_accepted() {
        let token = picky_asn1_der::to_vec(&tgt_req(NT_SRV_INST, "VM1.example.com", Some("EXAMPLE.COM"))).unwrap();

        accept_first_token(
            password_user(),
            &token,
            ServerRequestFlags::USE_SESSION_KEY | ServerRequestFlags::USE_DCE_STYLE,
        )
        .unwrap();
    }

    #[test]
    fn the_server_realm_is_decoded_next_to_the_server_name() {
        let decoded = decode_krb_message::<TgtReqWithRealm>(TGT_REQ_TOKEN_WITH_REALM, TGT_REQ_TOKEN_ID).unwrap();

        assert_eq!(decoded, tgt_req(NT_SRV_INST, "VM1.example.com", Some("EXAMPLE.COM")));
    }

    #[test]
    fn the_name_type_of_the_service_name_is_ignored() {
        // MIT-based clients use `NT-SRV-HST`, the acceptor is configured with `NT-SRV-INST`.
        let token = generate_krb_message(
            oids::krb5_user_to_user(),
            TGT_REQ_TOKEN_ID,
            tgt_req(NT_SRV_HST, "VM1.example.com", None),
        )
        .unwrap();

        accept_first_token(password_user(), &token, ServerRequestFlags::USE_SESSION_KEY).unwrap();
    }

    #[test]
    fn a_tgt_req_for_another_service_is_rejected() {
        let token = generate_krb_message(
            oids::krb5_user_to_user(),
            TGT_REQ_TOKEN_ID,
            tgt_req(NT_SRV_INST, "other.example.com", None),
        )
        .unwrap();

        let error = accept_first_token(password_user(), &token, ServerRequestFlags::USE_SESSION_KEY).unwrap_err();

        assert_eq!(error.error_type, ErrorKind::InvalidToken);
        assert!(error.description.contains("invalid ticket service name"), "{error}");
    }

    #[test]
    fn the_client_principal_is_available_only_once_the_context_is_established() {
        let cname = PrincipalName {
            name_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![NT_PRINCIPAL])),
            name_string: ExplicitContextTag1::from(Asn1SequenceOf::from(vec![KerberosStringAsn1::from(
                IA5String::from_string("alice".to_owned()).unwrap(),
            )])),
        };
        let crealm = KerberosStringAsn1::from(IA5String::from_string("EXAMPLE.COM".to_owned()).unwrap());
        let mut kerberos = fake_server();
        kerberos.client_principal = Some(ClientPrincipal::from_ticket(&cname, &crealm));

        kerberos.state = KerberosState::Server(KerberosServerState::ApExchange);
        assert!(kerberos.client_principal().is_none());

        kerberos.state = KerberosState::Final;
        assert_eq!(kerberos.client_principal().unwrap().components(), ["alice"]);
    }

    #[test]
    fn a_keytab_service_principal_is_sent_to_the_kdc_as_an_nt_principal_with_two_components() {
        let keytab = CredentialsBuffers::Keytab(KeytabIdentity {
            principal: Username::new_down_level_logon_name("TERMSRV/host.example.com", "EXAMPLE.COM").unwrap(),
            key: Secret::from(vec![0; 32]),
            key_enctype: CipherSuite::Aes256CtsHmacSha196,
        });
        let request =
            accept_first_token(keytab, TGT_REQ_TOKEN_WITH_REALM, ServerRequestFlags::USE_SESSION_KEY).unwrap();

        // The first four bytes are the length of the message.
        let as_req: AsReq = picky_asn1_der::from_bytes(&request.data[4..]).unwrap();
        let cname = as_req.0.req_body.0.cname.0.unwrap().0;
        assert_eq!(cname.name_type.0.0, vec![NT_PRINCIPAL]);
        assert_eq!(cname.name_string.0.0.len(), 2);
    }

    #[test]
    fn a_client_principal_keeps_every_component_and_the_case_of_the_realm() {
        let cname = PrincipalName {
            name_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![NT_PRINCIPAL])),
            name_string: ExplicitContextTag1::from(Asn1SequenceOf::from(vec![
                KerberosStringAsn1::from(IA5String::from_string("Alice".to_owned()).unwrap()),
                KerberosStringAsn1::from(IA5String::from_string("admin".to_owned()).unwrap()),
            ])),
        };
        let crealm = KerberosStringAsn1::from(IA5String::from_string("Example.COM".to_owned()).unwrap());

        let principal = ClientPrincipal::from_ticket(&cname, &crealm);

        assert_eq!(principal.components(), ["Alice", "admin"]);
        assert_eq!(principal.realm(), "Example.COM");
    }

    #[test]
    fn a_keytab_principal_without_a_realm_is_rejected() {
        let keytab = CredentialsBuffers::Keytab(KeytabIdentity {
            principal: Username::parse("host").unwrap(),
            key: Secret::from(vec![0; 32]),
            key_enctype: CipherSuite::Aes256CtsHmacSha196,
        });
        let error =
            accept_first_token(keytab, TGT_REQ_TOKEN_WITH_REALM, ServerRequestFlags::USE_SESSION_KEY).unwrap_err();

        assert!(error.description.contains("keytab principal has no realm"), "{error}");
    }

    #[test]
    fn a_tgt_req_without_a_server_name_is_rejected() {
        // Only `pvno` and `msg-type`.
        let token = [
            0x60, 0x1a, 0x06, 0x0a, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02, 0x03, 0x04, 0x00, 0x30, 0x0a,
            0xa0, 0x03, 0x02, 0x01, 0x05, 0xa1, 0x03, 0x02, 0x01, 0x10,
        ];

        let error = accept_first_token(password_user(), &token, ServerRequestFlags::USE_SESSION_KEY).unwrap_err();

        assert_eq!(error.error_type, ErrorKind::InvalidToken);
    }

    mod ap_req_validation {
        use picky_asn1::bit_string::BitString;
        use picky_asn1::date::GeneralizedTime;
        use picky_asn1::wrapper::ExplicitContextTag6;
        use picky_asn1::wrapper::{ExplicitContextTag4, ExplicitContextTag5, ExplicitContextTag7, OctetStringAsn1};
        use picky_krb::constants::key_usages::TICKET_REP;
        use picky_krb::crypto::aes::AesSize;
        use picky_krb::data_types::{
            Authenticator, EncTicketPart, EncTicketPartInner, EncryptedData, EncryptionKey, KerberosFlags,
            KerberosTime, Ticket, TicketInner, TransitedEncoding,
        };
        use rstest::rstest;
        use std::sync::{Arc, Mutex};
        use time::Duration as TimeDuration;

        use super::*;
        use crate::kerberos::client::generators::generate_ap_req;
        use crate::kerberos::flags::ApOptions as ApOptionsFlags;
        use crate::kerberos::{EncryptionParams, KERBEROS_VERSION};

        const SERVICE_KEY: [u8; 32] = [0x11; 32];
        const SESSION_KEY: [u8; 32] = [0x22; 32];
        const SUBKEY: [u8; 32] = [0x33; 32];
        const AP_REQ_MSG_TYPE: u8 = 14;
        /// The `INVALID` ticket flag is bit 7 of `TicketFlags`: the last bit of the first octet.
        const TICKET_FLAG_INVALID: u8 = 0b0000_0001;

        /// The parts of an AP-REQ that the acceptor must validate. [Default] is a valid request.
        struct Spec {
            ap_req_pvno: u8,
            ap_req_msg_type: u8,
            ticket_vno: u8,
            authenticator_vno: u8,
            ticket_flags: u8,
            mutual_auth: bool,
            /// The encryption type of the ticket, of its session key and of the authenticator.
            cipher_suite: CipherSuite,
            /// The encryption type of the subkey in the authenticator, if the initiator sends one.
            authenticator_subkey: Option<CipherSuite>,
        }

        impl Default for Spec {
            fn default() -> Self {
                Self {
                    ap_req_pvno: KERBEROS_VERSION,
                    ap_req_msg_type: AP_REQ_MSG_TYPE,
                    ticket_vno: KERBEROS_VERSION,
                    authenticator_vno: KERBEROS_VERSION,
                    ticket_flags: 0,
                    mutual_auth: false,
                    cipher_suite: CipherSuite::Aes256CtsHmacSha196,
                    authenticator_subkey: None,
                }
            }
        }

        fn string(value: &str) -> KerberosStringAsn1 {
            KerberosStringAsn1::from(IA5String::from_string(value.to_owned()).unwrap())
        }

        fn alice() -> PrincipalName {
            PrincipalName {
                name_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![NT_PRINCIPAL])),
                name_string: ExplicitContextTag1::from(Asn1SequenceOf::from(vec![string("alice")])),
            }
        }

        fn time(value: OffsetDateTime) -> KerberosTime {
            KerberosTime::from(GeneralizedTime::from(value))
        }

        /// The first octets of the key material, as long as the keys of the encryption type.
        fn key(material: &[u8; 32], cipher_suite: &CipherSuite) -> Vec<u8> {
            material[..cipher_suite.cipher().key_size()].to_vec()
        }

        /// Encrypts the encoded `EncTicketPart` with the service key.
        fn encrypted_ticket_part(cipher_suite: &CipherSuite, data: &[u8]) -> EncryptedData {
            EncryptedData {
                etype: ExplicitContextTag0::from(IntegerAsn1::from(vec![cipher_suite.into()])),
                kvno: Optional::from(None),
                cipher: ExplicitContextTag2::from(OctetStringAsn1::from(
                    cipher_suite
                        .cipher()
                        .encrypt(&key(&SERVICE_KEY, cipher_suite), TICKET_REP, data)
                        .unwrap(),
                )),
            }
        }

        fn ap_req(spec: &Spec) -> ApReq {
            let now = OffsetDateTime::now_utc();
            let service_name = fake_server().server.unwrap().service_name;

            let enc_ticket_part = EncTicketPart::from(EncTicketPartInner {
                flags: ExplicitContextTag0::from(KerberosFlags::from(BitString::with_bytes(vec![
                    spec.ticket_flags,
                    0,
                    0,
                    0,
                ]))),
                key: ExplicitContextTag1::from(EncryptionKey {
                    key_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![(&spec.cipher_suite).into()])),
                    key_value: ExplicitContextTag1::from(OctetStringAsn1::from(key(&SESSION_KEY, &spec.cipher_suite))),
                }),
                crealm: ExplicitContextTag2::from(string("EXAMPLE.COM")),
                cname: ExplicitContextTag3::from(alice()),
                transited: ExplicitContextTag4::from(TransitedEncoding {
                    tr_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![0])),
                    contents: ExplicitContextTag1::from(OctetStringAsn1::from(Vec::new())),
                }),
                auth_time: ExplicitContextTag5::from(time(now - TimeDuration::minutes(1))),
                starttime: Optional::from(None),
                endtime: ExplicitContextTag7::from(time(now + TimeDuration::hours(1))),
                renew_till: Optional::from(None),
                caddr: Optional::from(None),
                authorization_data: Optional::from(None),
            });
            let ticket = Ticket::from(TicketInner {
                tkt_vno: ExplicitContextTag0::from(IntegerAsn1::from(vec![spec.ticket_vno])),
                realm: ExplicitContextTag1::from(string("EXAMPLE.COM")),
                sname: ExplicitContextTag2::from(service_name),
                enc_part: ExplicitContextTag3::from(encrypted_ticket_part(
                    &spec.cipher_suite,
                    &picky_asn1_der::to_vec(&enc_ticket_part).unwrap(),
                )),
            });

            let authenticator = Authenticator::from(AuthenticatorInner {
                authenticator_vno: ExplicitContextTag0::from(IntegerAsn1::from(vec![spec.authenticator_vno])),
                crealm: ExplicitContextTag1::from(string("EXAMPLE.COM")),
                cname: ExplicitContextTag2::from(alice()),
                cksum: Optional::from(None),
                cusec: ExplicitContextTag4::from(IntegerAsn1::from(vec![0])),
                ctime: ExplicitContextTag5::from(time(now)),
                subkey: Optional::from(spec.authenticator_subkey.as_ref().map(|subkey_suite| {
                    ExplicitContextTag6::from(EncryptionKey {
                        key_type: ExplicitContextTag0::from(IntegerAsn1::from(vec![subkey_suite.into()])),
                        key_value: ExplicitContextTag1::from(OctetStringAsn1::from(key(&SUBKEY, subkey_suite))),
                    })
                })),
                seq_number: Optional::from(None),
                authorization_data: Optional::from(None),
            });

            let mut ap_req = generate_ap_req(
                ticket,
                &Secret::new(key(&SESSION_KEY, &spec.cipher_suite)),
                &authenticator,
                &EncryptionParams {
                    encryption_type: Some(spec.cipher_suite.clone()),
                    ..EncryptionParams::default_for_client()
                },
                if spec.mutual_auth {
                    ApOptionsFlags::MUTUAL_REQUIRED
                } else {
                    ApOptionsFlags::empty()
                },
            )
            .unwrap();
            ap_req.0.pvno = ExplicitContextTag0::from(IntegerAsn1::from(vec![spec.ap_req_pvno]));
            ap_req.0.msg_type = ExplicitContextTag1::from(IntegerAsn1::from(vec![spec.ap_req_msg_type]));

            ap_req
        }

        fn acceptor() -> Kerberos {
            acceptor_for(&CipherSuite::Aes256CtsHmacSha196)
        }

        /// The acceptor of a service whose key has the given encryption type.
        fn acceptor_for(cipher_suite: &CipherSuite) -> Kerberos {
            let mut kerberos = fake_server();
            // The acceptor learns the encryption type and the keys from the AP-REQ, not from its configuration.
            kerberos.encryption_params.encryption_type = None;
            kerberos.encryption_params.session_key = None;
            kerberos.encryption_params.sub_session_key = None;
            kerberos.server.as_mut().unwrap().ticket_decryption_key =
                Some(Secret::new(key(&SERVICE_KEY, cipher_suite)));

            kerberos
        }

        fn accept(spec: &Spec) -> Result<AcceptSecurityContextResult> {
            accept_token(
                &mut acceptor_for(&spec.cipher_suite),
                &picky_asn1_der::to_vec(&ap_req(spec)).unwrap(),
            )
        }

        fn accept_token(kerberos: &mut Kerberos, token: &[u8]) -> Result<AcceptSecurityContextResult> {
            accept_token_with_output(kerberos, token).map(|(result, _output)| result)
        }

        /// Feeds the encoded AP-REQ to the acceptor as the first token of a new context.
        ///
        /// Returns the result and the output token.
        fn accept_token_with_output(
            kerberos: &mut Kerberos,
            token: &[u8],
        ) -> Result<(AcceptSecurityContextResult, Vec<u8>)> {
            kerberos.state = KerberosState::Server(KerberosServerState::Preauthentication);

            let mut credentials_handle: Option<CredentialsBuffers> = None;
            let mut input = [SecurityBuffer::new(token.to_vec(), BufferType::Token)];
            let mut output = [SecurityBuffer::new(Vec::new(), BufferType::Token)];
            let builder = kerberos
                .accept_security_context()
                .with_credentials_handle(&mut credentials_handle)
                .with_context_requirements(ServerRequestFlags::USE_DCE_STYLE)
                .with_target_data_representation(DataRepresentation::Native)
                .with_input(&mut input)
                .with_output(&mut output);
            let mut generator = SspiImpl::accept_security_context_impl(kerberos, builder)?;

            let result = match generator.start() {
                GeneratorState::Completed(result) => result?,
                GeneratorState::Suspended(_) => {
                    return Err(Error::new(ErrorKind::InternalError, "unexpected KDC request"));
                }
            };
            drop(generator);

            let [output] = output;

            Ok((result, output.buffer))
        }

        // The control: the other cases differ from this request in exactly one field.
        #[test]
        fn a_valid_ap_req_is_accepted() {
            accept(&Spec::default()).unwrap();
        }

        // RFC 4120 §3.2.3: KRB_AP_ERR_BADVERSION for an unsupported version, KRB_AP_ERR_MSG_TYPE for a wrong type.
        #[rstest]
        #[case::ap_req_version(Spec { ap_req_pvno: 4, ..Spec::default() })]
        #[case::ap_req_message_type(Spec { ap_req_msg_type: 13, ..Spec::default() })]
        #[case::ticket_version(Spec { ticket_vno: 4, ..Spec::default() })]
        #[case::authenticator_version(Spec { authenticator_vno: 4, ..Spec::default() })]
        // RFC 4120 §3.2.3: a ticket with the INVALID flag set is not usable until validated (KRB_AP_ERR_TKT_NYV).
        #[case::invalid_ticket(Spec { ticket_flags: TICKET_FLAG_INVALID, ..Spec::default() })]
        fn a_malformed_ap_req_is_rejected(#[case] spec: Spec) {
            let error = accept(&spec).unwrap_err();

            assert_eq!(error.error_type, ErrorKind::InvalidToken, "{error}");
        }

        fn aes128_spec() -> Spec {
            Spec {
                cipher_suite: CipherSuite::Aes128CtsHmacSha196,
                ..Spec::default()
            }
        }

        // RFC 4120 §5.5.2: the AP-REP is encrypted with the session key, so with its encryption type.
        #[test]
        fn the_ap_rep_follows_the_encryption_type_of_the_session_key() {
            let spec = Spec {
                mutual_auth: true,
                ..aes128_spec()
            };
            let mut kerberos = acceptor_for(&spec.cipher_suite);
            let token = picky_asn1_der::to_vec(&ap_req(&spec)).unwrap();

            let (_, ap_rep) = accept_token_with_output(&mut kerberos, &token).unwrap();

            let ap_rep: ApRep = picky_asn1_der::from_bytes(&ap_rep).unwrap();
            assert_eq!(ap_rep.0.enc_part.0.etype.0.0, [17]);
            let enc_part = decrypt_ap_rep(
                &ap_rep,
                &Secret::new(key(&SESSION_KEY, &spec.cipher_suite)),
                &EncryptionParams {
                    encryption_type: Some(spec.cipher_suite),
                    ..EncryptionParams::default_for_client()
                },
            )
            .unwrap();
            let subkey = enc_part.0.subkey.0.expect("the acceptor sends its subkey").0;
            assert_eq!(subkey.key_type.0.0, [17]);
            assert_eq!(subkey.key_value.0.0.len(), 16);
        }

        /// Accepts the AP-REQ without mutual authentication, and returns the acceptor
        /// together with the result of unwrapping an integrity-only token that the initiator protects with `token_key`.
        fn unwrap_integrity_only_token(spec: &Spec, token_key: &[u8], aes_size: AesSize) -> Result<Vec<u8>> {
            use picky_krb::constants::key_usages::INITIATOR_SEAL;
            use picky_krb::crypto::aes::checksum_sha_aes;
            use picky_krb::gss_api::WrapToken;

            use crate::{SecurityBufferRef, Sspi};

            let mut kerberos = acceptor_for(&spec.cipher_suite);
            let token = picky_asn1_der::to_vec(&ap_req(spec)).unwrap();
            accept_token(&mut kerberos, &token).unwrap();

            // Sent by the initiator, not sealed. The checksum covers `plaintext | header`, with EC and RRC zero.
            let plaintext = b"integrity-only payload";
            let mut wrap_token = WrapToken::with_seq_number(0);
            wrap_token.flags = 0;
            let mut to_sign = plaintext.to_vec();
            to_sign.extend_from_slice(&wrap_token.header());
            let checksum = checksum_sha_aes(token_key, INITIATOR_SEAL, &to_sign, &aes_size).unwrap();
            let mut payload = plaintext.to_vec();
            payload.extend_from_slice(&checksum);
            wrap_token.ec = u16::try_from(checksum.len()).unwrap();
            wrap_token.rrc = 0;
            wrap_token.checksum = payload;
            let mut raw_token = Vec::new();
            wrap_token.encode(&mut raw_token).unwrap();

            let mut message = [
                SecurityBufferRef::stream_buf(&mut raw_token),
                SecurityBufferRef::data_buf(&mut []),
            ];
            kerberos.decrypt_message(&mut message)?;

            assert_eq!(message[1].data(), plaintext);

            Ok(message[1].data().to_vec())
        }

        // RFC 4121 §4.2.4: the integrity-only Wrap token is checked with the checksum of the key encryption type.
        #[test]
        fn an_integrity_only_wrap_token_is_verified_for_an_aes128_ticket() {
            let spec = aes128_spec();

            unwrap_integrity_only_token(&spec, &key(&SESSION_KEY, &spec.cipher_suite), AesSize::Aes128).unwrap();
        }

        // RFC 4121 §2: a subkey in the authenticator protects the per-message tokens, whatever the ticket encryption type.
        #[test]
        fn an_integrity_only_wrap_token_follows_the_encryption_type_of_the_authenticator_subkey() {
            let spec = Spec {
                authenticator_subkey: Some(CipherSuite::Aes128CtsHmacSha196),
                ..Spec::default()
            };

            unwrap_integrity_only_token(&spec, &key(&SUBKEY, &CipherSuite::Aes128CtsHmacSha196), AesSize::Aes128)
                .unwrap();
        }

        /// Returns the raw `seq-number` INTEGER of the AP-REP that the acceptor sends for a mutual authentication.
        fn ap_rep_seq_number(acceptor_seq_number: u32) -> Vec<u8> {
            let mut kerberos = acceptor();
            kerberos.seq_number = acceptor_seq_number;
            let token = picky_asn1_der::to_vec(&ap_req(&Spec {
                mutual_auth: true,
                ..Spec::default()
            }))
            .unwrap();

            let (_, ap_rep) = accept_token_with_output(&mut kerberos, &token).unwrap();

            let ap_rep: ApRep = picky_asn1_der::from_bytes(&ap_rep).unwrap();
            let enc_part = decrypt_ap_rep(
                &ap_rep,
                &Secret::new(SESSION_KEY.to_vec()),
                &EncryptionParams::default_for_client(),
            )
            .unwrap();

            enc_part.0.seq_number.0.unwrap().0.0
        }

        // RFC 4120 §5.1 requires the DER encoding: a `u32` with the high bit set is not a negative INTEGER, and the
        // sequence number wraps around at 2^32 (RFC 4120 §5.3.2).
        #[rstest]
        #[case::small(1, &[0x02])]
        #[case::high_bit_set(0x9abc_dee9, &[0x00, 0x9a, 0xbc, 0xde, 0xea])]
        #[case::wraps_around(u32::MAX, &[0x00])]
        fn the_ap_rep_sequence_number_is_the_next_one_in_minimal_der(
            #[case] acceptor_seq_number: u32,
            #[case] expected: &[u8],
        ) {
            assert_eq!(ap_rep_seq_number(acceptor_seq_number), expected);
        }

        // RFC 4120 §3.2.3: the acceptor must remember the authenticators presented within the clock skew.
        #[test]
        fn a_replayed_authenticator_is_rejected() {
            let token = picky_asn1_der::to_vec(&ap_req(&Spec::default())).unwrap();
            let mut kerberos = acceptor();

            accept_token(&mut kerberos, &token).unwrap();
            let error = accept_token(&mut kerberos, &token).unwrap_err();

            assert_eq!(error.error_type, ErrorKind::InvalidToken, "{error}");
            assert!(error.description.contains("replay"), "{error}");
        }

        // The cache is managed by the caller, who shares it between the contexts that serve the same service.
        // Otherwise a replay against a new connection is accepted.
        #[test]
        fn a_replay_is_detected_by_another_context_that_shares_the_cache() {
            let cache = Arc::new(Mutex::new(AuthenticatorsCache::default()));
            let mut first = acceptor();
            first.server.as_mut().unwrap().authenticators_cache = Arc::clone(&cache);
            let mut second = acceptor();
            second.server.as_mut().unwrap().authenticators_cache = cache;
            let token = picky_asn1_der::to_vec(&ap_req(&Spec::default())).unwrap();

            accept_token(&mut first, &token).unwrap();
            let error = accept_token(&mut second, &token).unwrap_err();

            assert!(error.description.contains("replay"), "{error}");
        }

        #[test]
        fn contexts_with_separate_caches_do_not_see_each_others_authenticators() {
            let token = picky_asn1_der::to_vec(&ap_req(&Spec::default())).unwrap();

            accept_token(&mut acceptor(), &token).unwrap();
            accept_token(&mut acceptor(), &token).unwrap();
        }

        // An authenticator older than the clock skew is rejected by the time check, so the cache never needs
        // to remember it. Keeping it makes the cache of a long-running acceptor grow without bound.
        #[test]
        fn authenticators_outside_the_clock_skew_are_dropped_from_the_replay_cache() {
            let mut kerberos = acceptor();
            let server_data = kerberos.server.as_mut().unwrap();
            let max_time_skew = server_data.max_time_skew;
            let stale_ctime = OffsetDateTime::now_utc() - max_time_skew - TimeDuration::minutes(1);
            server_data
                .authenticators_cache
                .lock()
                .unwrap()
                .insert(AuthenticatorCacheRecord {
                    cname: alice(),
                    sname: server_data.service_name.clone(),
                    ctime: GeneralizedTime::from(stale_ctime).into(),
                    microseconds: IntegerAsn1::from(vec![0]),
                });

            let token = picky_asn1_der::to_vec(&ap_req(&Spec::default())).unwrap();
            accept_token(&mut kerberos, &token).unwrap();

            assert_eq!(
                kerberos
                    .server
                    .as_ref()
                    .unwrap()
                    .authenticators_cache
                    .lock()
                    .unwrap()
                    .len(),
                1
            );
        }
    }
}
