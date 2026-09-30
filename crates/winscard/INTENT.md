This crate implements emulated PIV-compatible smart cards.
The goal is to provide scard logon without a need of a real smart card or even a virtual smart card minidriver.

The implementation follows the PIV smart card specification.
Thus, Windows is able to authorize the logon using its built-in minidriver.

## Specifications

* [NIST.SP.800-73-4](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf).
