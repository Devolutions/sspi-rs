use bitflags::bitflags;

bitflags! {
    /// This flags appears in the KRB_AS_REQ and KRB_TGS_REQ requests to
    /// the KDC and indicates the flags that the client wants set on the tickets.
    ///
    /// [KDCOptions](https://www.rfc-editor.org/rfc/rfc4120#section-5.4.1)
    pub struct KdcOptions: u32 {
        const FORWARDABLE = 0b01000000_00000000_00000000_00000000;
        const FORWARDED = 0b00100000_00000000_00000000_00000000;
        const PROXIABLE = 0b00010000_00000000_00000000_00000000;
        const PROXY = 0b00001000_00000000_00000000_00000000;
        const ALLOW_POSTDATE = 0b00000100_00000000_00000000_00000000;
        const POSTDATED = 0b00000010_00000000_00000000_00000000;
        const RENEWABLE = 0b00000000_10000000_00000000_00000000;
        const OPT_HARDWARE_AUTH = 0b00000000_00010000_00000000_00000000;
        const CANONICALIZE = 0b00000000_00000001_00000000_00000000;
        const DISABLE_TRANSITED_CHECK = 0b00000000_00000000_00000000_00100000;
        const RENEWABLE_OK = 0b00000000_00000000_00000000_00010000;
        const ENC_TKT_IN_SKEY = 0b00000000_00000000_00000000_00001000;
        const RENEW = 0b00000000_00000000_00000000_00000010;
        const VALIDATE = 0b00000000_00000000_00000000_00000001;
    }
}
