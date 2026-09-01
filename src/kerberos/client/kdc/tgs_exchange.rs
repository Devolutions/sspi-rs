use crate::Result;
use crate::channel_bindings::ChannelBindings;
use crate::kerberos::EncryptionParams;
use crate::kerberos::client::extractors::extract_session_key_from_tgs_rep;
use crate::kerberos::client::generators::{
    GenerateAuthenticatorOptions, GenerateTgsReqOptions, generate_authenticator, generate_tgs_req,
};
use crate::kerberos::client::kdc::decode_kdc_reply;
use crate::kerberos::client::referral_target_realm;
use crate::{ClientRequestFlags, Error, ErrorKind, Secret};
use hmac::digest::common::getrandom::SysRng;
use picky_krb::data_types::Ticket;
use picky_krb::messages::{IAKerbCookie, KdcRep, TgsRep, TgsReq};
use rand::prelude::StdRng;
use rand_core::{Rng, SeedableRng};

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
    iakerb: bool,
    realm: String,
    ticket: Option<Ticket>,
    tgt_session_key: Secret<Vec<u8>>,
    auth_rep: KdcRep,
    additional_tickets: Option<Vec<Ticket>>,
    hops: usize,
    context_requirements: ClientRequestFlags,
}

impl TgsExchange {
    pub(crate) fn new(
        iakerb: bool,
        realm: String,
        ticket: Ticket,
        tgt_session_key: Secret<Vec<u8>>,
        auth_rep: KdcRep,
        additional_tickets: Option<Vec<Ticket>>,
        context_requirements: ClientRequestFlags,
    ) -> Self {
        Self {
            state: TgsExchangeState::TgsRequest,
            iakerb,
            realm,
            ticket: Some(ticket),
            tgt_session_key,
            auth_rep,
            additional_tickets,
            hops: 0,
            context_requirements,
        }
    }

    pub(crate) fn step<'a>(
        &'a mut self,
        channel_bindings: Option<&ChannelBindings>,
        enc_params: &EncryptionParams,
        service_principal: &str,
        response: &[u8],
        iakerb_cookie: &mut IAKerbCookie,
        iakerb_gss_transcript: &mut Vec<u8>,
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

                    let mut authenticator = generate_authenticator(GenerateAuthenticatorOptions {
                        kdc_rep: &self.auth_rep,
                        seq_num: Some(rand.next_u32()),
                        sub_key: None,
                        checksum: None,
                        channel_bindings,
                        extensions: Vec::new(),
                    })?;

                    let tgs_req = generate_tgs_req(GenerateTgsReqOptions {
                        realm: &self.realm,
                        service_principal,
                        session_key: &self.tgt_session_key,
                        ticket: self
                            .ticket
                            .take()
                            .ok_or_else(|| Error::new(ErrorKind::InternalError, "ticket is missing"))?,
                        authenticator: &mut authenticator,
                        additional_tickets: self.additional_tickets.take(),
                        enc_params,
                        context_requirements: self.context_requirements,
                    })?;

                    self.state = TgsExchangeState::TgsResponse;

                    return Ok(TgsExchangeOutput::SendRequest((tgs_req, &self.realm)));
                }
                TgsExchangeState::TgsResponse => {
                    if response.is_empty() {
                        return Err(Error::new(ErrorKind::InternalError, "the KDC reply message is absent"));
                    }

                    let tgs_rep = decode_kdc_reply(response, self.iakerb, iakerb_cookie, iakerb_gss_transcript)?;
                    let tgs_rep = tgs_rep.inspect_err(|err| error!(?err, "TGS exchange error"))?;

                    let session_key = extract_session_key_from_tgs_rep(&tgs_rep, &self.tgt_session_key, enc_params)?;

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
                }
            }
        }
    }
}
