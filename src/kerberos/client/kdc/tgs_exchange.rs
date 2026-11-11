use picky_asn1::wrapper::IntegerAsn1;
use picky_krb::data_types::Ticket;
use picky_krb::messages::{KdcRep, TgsRep, TgsReq};
use rand::rngs::{StdRng, SysRng};
use rand_core::{Rng, SeedableRng};

use crate::kerberos::client::extractors::{SessionKey, extract_checked_tgs_session_key};
use crate::kerberos::client::generators::{
    GenerateAuthenticatorOptions, GenerateTgsReqOptions, generate_authenticator_at, generate_tgs_req,
};
use crate::kerberos::client::kdc::decode_kdc_reply;
use crate::kerberos::client::referral_target_realm;
use crate::rcg::CapturedTgt;
use crate::{ClientRequestFlags, Error, ErrorKind, Kerberos, Result, Secret};

const MAX_REFERRAL_HOPS: usize = 10;

pub(crate) enum TgsExchangeOutput<'a> {
    SendRequest((TgsReq, &'a str)),
    Done((TgsRep, Secret<Vec<u8>>)),
}

#[derive(Debug, Clone, PartialEq)]
enum TgsExchangeState {
    TgsRequest,
    TgsResponse,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TgsExchange {
    state: TgsExchangeState,
    realm: String,
    ticket: Option<Ticket>,
    tgt_session_key: Secret<Vec<u8>>,
    auth_rep: KdcRep,
    additional_tickets: Option<Vec<Ticket>>,
    hops: usize,
    context_requirements: ClientRequestFlags,
    /// The nonce of the last TGS-REQ, which the TGS-REP must echo.
    request_nonce: Option<IntegerAsn1>,
}

impl TgsExchange {
    pub(crate) fn new(
        realm: String,
        ticket: Ticket,
        tgt_session_key: Secret<Vec<u8>>,
        auth_rep: KdcRep,
        additional_tickets: Option<Vec<Ticket>>,
        context_requirements: ClientRequestFlags,
    ) -> Self {
        Self {
            state: TgsExchangeState::TgsRequest,
            realm,
            ticket: Some(ticket),
            tgt_session_key,
            auth_rep,
            additional_tickets,
            hops: 0,
            context_requirements,
            request_nonce: None,
        }
    }

    pub(crate) fn step<'a>(
        &'a mut self,
        client: &mut Kerberos,
        service_principal: &str,
        response: &[u8],
    ) -> Result<TgsExchangeOutput<'a>> {
        // Cross-realm referral chasing (RFC 4120 §3.3.3.2 / MS-KILE).
        //
        // * [Cross-Realm Operation](https://www.rfc-editor.org/rfc/rfc4120.html#section-1.2)
        // * [Server Referrals](https://www.rfc-editor.org/rfc/rfc6806.html#section-8)
        //
        // A KDC can only issue tickets for principals in its own realm. When the requested
        // service lives in another realm (e.g. a user in `RJM.LOCAL` targeting a host in the
        // child realm `DEV.RJM.LOCAL`), the KDC does not return the service ticket. Instead it
        // returns a referral TGT whose `sname` is `krbtgt/<NEXT_REALM>`, and the client must
        // re-issue the TGS-REQ for the same service to `<NEXT_REALM>`'s KDC using that referral
        // TGT. We loop until the returned ticket's `sname` matches the requested service (i.e.
        // it is no longer a `krbtgt/...` referral).
        //
        // The referral hop is routed via `send_for_realm`, which resolves the target realm's
        // KDC through `SSPI_KDC_URL_<REALM>` (env) / krb5.conf / DNS SRV rather than the pinned
        // home-realm KDC, which cannot decrypt a `krbtgt/<NEXT_REALM>` referral ticket.
        //
        // NOTE: this referral-chasing branch is not exercised under IAKerb. The LocalKDC returns
        // the final service ticket directly, so `referral_target_realm` never observes `sname` of
        // the form `krbtgt/<NEXT_REALM>` and the TGS exchange always finishes on the first response.
        loop {
            match self.state {
                TgsExchangeState::TgsRequest => {
                    let mut rand = StdRng::try_from_rng(&mut SysRng)?;

                    let now = client.current_kdc_time()?;
                    let mut authenticator = generate_authenticator_at(
                        GenerateAuthenticatorOptions {
                            kdc_rep: &self.auth_rep,
                            seq_num: Some(rand.next_u32()),
                            sub_key: None,
                            checksum: None,
                            channel_bindings: client.channel_bindings.as_ref(),
                            extensions: Vec::new(),
                        },
                        now,
                    )?;

                    let ticket = self
                        .ticket
                        .take()
                        .ok_or_else(|| Error::new(ErrorKind::InternalError, "ticket is missing"))?;
                    if let Some(remote_guard) = client.remote_guard.as_deref_mut() {
                        remote_guard.service_tgt =
                            Some(CapturedTgt::new(
                                self.realm.clone(),
                                ticket.clone(),
                                client.encryption_params.encryption_type.clone().ok_or_else(|| {
                                    Error::new(ErrorKind::InternalError, "encryption type is not set")
                                })?,
                                self.tgt_session_key.clone(),
                            )?);
                    }

                    let tgs_req = generate_tgs_req(GenerateTgsReqOptions {
                        realm: &self.realm,
                        service_principal,
                        session_key: &self.tgt_session_key,
                        ticket,
                        authenticator: &mut authenticator,
                        additional_tickets: self.additional_tickets.take(),
                        enc_params: &client.encryption_params,
                        context_requirements: self.context_requirements,
                    })?;

                    self.request_nonce = Some(tgs_req.0.req_body.0.nonce.0.clone());
                    self.state = TgsExchangeState::TgsResponse;

                    return Ok(TgsExchangeOutput::SendRequest((tgs_req, &self.realm)));
                }
                TgsExchangeState::TgsResponse => {
                    if response.is_empty() {
                        return Err(Error::new(ErrorKind::InternalError, "the KDC reply message is absent"));
                    }

                    let tgs_rep = decode_kdc_reply(
                        response,
                        client.is_iakerb(),
                        &mut client.iakerb_cookie,
                        &mut client.iakerb_gss_transcript,
                    )?;
                    let tgs_rep = tgs_rep.inspect_err(|err| error!(?err, "TGS exchange error"))?;

                    let request_nonce = self
                        .request_nonce
                        .as_ref()
                        .ok_or_else(|| Error::new(ErrorKind::OutOfSequence, "TGS-REQ nonce is not set"))?;
                    let SessionKey { key, cipher_suite } =
                        extract_checked_tgs_session_key(&tgs_rep, &self.tgt_session_key, request_nonce)?;
                    let session_key = key;
                    // The next message is protected with this key: a referral TGT request, or the AP-REQ.
                    client.encryption_params.encryption_type = Some(cipher_suite);

                    // A referral TGT is identified by an `sname` of the form `krbtgt/<NEXT_REALM>`.
                    let Some(next_realm) = referral_target_realm(&tgs_rep.0.ticket.0.0.sname.0) else {
                        debug!("TGS exchange finished successfully");
                        return Ok(TgsExchangeOutput::Done((tgs_rep, session_key)));
                    };
                    debug!(%self.realm, %next_realm, "Received cross-realm referral TGT; chasing referral");

                    self.hops += 1;
                    if self.hops >= MAX_REFERRAL_HOPS {
                        return Err(Error::new(
                            ErrorKind::NoAuthenticatingAuthority,
                            format!(
                                "exceeded maximum Kerberos referral hops ({MAX_REFERRAL_HOPS}) resolving {service_principal}"
                            ),
                        ));
                    }
                    if next_realm.eq_ignore_ascii_case(&self.realm) {
                        return Err(Error::new(
                            ErrorKind::NoAuthenticatingAuthority,
                            format!("Kerberos referral did not progress past realm `{}`", self.realm),
                        ));
                    }

                    self.ticket = Some(tgs_rep.0.ticket.0.clone());
                    self.tgt_session_key = session_key;
                    self.auth_rep = tgs_rep.0;
                    self.realm = next_realm;
                    self.state = TgsExchangeState::TgsRequest;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{TgsExchange, TgsExchangeOutput};
    use crate::ClientRequestFlags;
    use picky_krb::crypto::CipherSuite;

    use crate::kerberos::client::extractors::as_rep_regressions::{encrypted_tgs_rep, encrypted_tgs_rep_with_key};
    use crate::kerberos::test_data::fake_client;

    /// Performs the first step of the exchange, and returns the exchange and the nonce of its TGS-REQ.
    ///
    /// The reply is the referral TGT for `krbtgt/NEXT.EXAMPLE` with the given nonce.
    fn exchange_and_reply(reply_nonce: impl FnOnce(Vec<u8>) -> Vec<u8>) -> (TgsExchange, Vec<u8>) {
        let (template, tgt_session_key) = encrypted_tgs_rep(vec![0], &["krbtgt", "NEXT.EXAMPLE"], "NEXT.EXAMPLE");
        let mut exchange = TgsExchange::new(
            "HOME.EXAMPLE".to_owned(),
            template.0.ticket.0.clone(),
            tgt_session_key.clone(),
            template.0.clone(),
            None,
            ClientRequestFlags::empty(),
        );

        let TgsExchangeOutput::SendRequest((tgs_req, _realm)) = exchange
            .step(&mut fake_client(), "TERMSRV/host.example.com", &[])
            .unwrap()
        else {
            panic!("the exchange must start with a request");
        };
        let request_nonce = tgs_req.0.req_body.0.nonce.0.0.clone();

        // The reply is encrypted with the session key of the TGT that the exchange holds.
        let (reply, _) = encrypted_tgs_rep(reply_nonce(request_nonce), &["krbtgt", "NEXT.EXAMPLE"], "NEXT.EXAMPLE");
        // The first four bytes are the length of the message.
        let mut response = vec![0, 0, 0, 0];
        response.extend_from_slice(&picky_asn1_der::to_vec(&reply).unwrap());

        (exchange, response)
    }

    // RFC 4120 §3.3.5: a reply that does not echo the nonce of the request is not a reply to it.
    #[test]
    fn a_reply_with_the_nonce_of_the_request_is_accepted() {
        let (mut exchange, response) = exchange_and_reply(|request_nonce| request_nonce);

        // The referral TGT is followed by the request to the next realm.
        let output = exchange
            .step(&mut fake_client(), "TERMSRV/host.example.com", &response)
            .unwrap();

        assert!(matches!(output, TgsExchangeOutput::SendRequest(_)));
    }

    #[test]
    fn a_reply_with_another_nonce_is_rejected() {
        let (mut exchange, response) = exchange_and_reply(|mut request_nonce| {
            *request_nonce.last_mut().unwrap() ^= 1;
            request_nonce
        });

        let result = exchange.step(&mut fake_client(), "TERMSRV/host.example.com", &response);

        assert!(result.is_err());
    }

    // The service ticket session key has the encryption type that the service decides, not the one of the TGT.
    // The AP-REQ authenticator is encrypted with it.
    #[test]
    fn the_client_follows_the_encryption_type_of_the_service_ticket_session_key() {
        let (template, tgt_session_key) = encrypted_tgs_rep(vec![0], &["krbtgt", "NEXT.EXAMPLE"], "NEXT.EXAMPLE");
        let mut client = fake_client();
        client.encryption_params.encryption_type = Some(CipherSuite::Aes256CtsHmacSha196);
        let mut exchange = TgsExchange::new(
            "HOME.EXAMPLE".to_owned(),
            template.0.ticket.0.clone(),
            tgt_session_key,
            template.0.clone(),
            None,
            ClientRequestFlags::empty(),
        );
        let TgsExchangeOutput::SendRequest((tgs_req, _realm)) =
            exchange.step(&mut client, "TERMSRV/host.example.com", &[]).unwrap()
        else {
            panic!("the exchange must start with a request");
        };
        let (reply, _) = encrypted_tgs_rep_with_key(
            tgs_req.0.req_body.0.nonce.0.0.clone(),
            "HOME.EXAMPLE",
            &["TERMSRV", "host.example.com"],
            &["TERMSRV", "host.example.com"],
            "HOME.EXAMPLE",
            &CipherSuite::Aes128CtsHmacSha196,
        );
        let mut response = vec![0, 0, 0, 0];
        response.extend_from_slice(&picky_asn1_der::to_vec(&reply).unwrap());

        let TgsExchangeOutput::Done((_tgs_rep, session_key)) = exchange
            .step(&mut client, "TERMSRV/host.example.com", &response)
            .unwrap()
        else {
            panic!("the service ticket must complete the exchange");
        };

        assert_eq!(session_key.as_ref().len(), 16);
        assert_eq!(
            client.encryption_params.encryption_type,
            Some(CipherSuite::Aes128CtsHmacSha196)
        );
    }
}
