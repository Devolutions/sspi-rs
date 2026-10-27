# DPAPI core maintenance

Keep this crate compatible with `no_std`; feature-gate code that needs `std`.
Do not introduce I/O here.
Keep PDU implementations in `dpapi-pdu`.
