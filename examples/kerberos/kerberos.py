# filepath: c:\dev\sspi-rs\examples\kerberos\kerberos.py
import base64
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union, ByteString

import requests
import sspicon
import win32security


def get_credentials(username: str, domain: str, password: str):
    """
    Acquire Kerberos credentials using the provided username, domain, and password.

    Returns:
        Tuple containing the credential handle and expiration time.
    """
    return win32security.AcquireCredentialsHandle(
        None,
        "Kerberos",
        win32security.SECPKG_CRED_OUTBOUND,
        None,
        (username, domain, password),
    )


def send_http(
    hostname: str,
    session: requests.Session,
    auth: Optional[str] = None,
    body: Optional[Union[str, bytes]] = None,
) -> requests.Response:
    """
    Send an HTTP request to the specified host.

    Args:
        hostname: Target hostname
        session: Requests session object
        auth: Optional authorization header value
        body: Optional request body

    Returns:
        HTTP response object
    """
    url = f"http://{hostname}:5985/wsman?PSVersion=7.3.8"
    headers: Dict[str, str] = {
        "HOST": f"{hostname}:5985",
        "CONNECTION": "keep-alive",
        "CONTENT-LENGTH": str(len(body) if body else 0),
        "USER-AGENT": "Mozilla/5.0",
        "ACCEPT": "*/*",
        "ACCEPT-ENCODING": "gzip, deflate",
        "ACCEPT-LANGUAGE": "en-US,en;q=0.9",
    }
    if auth:
        headers["AUTHORIZATION"] = auth

    resp = session.post(url, headers=headers, data=body or "")
    return resp


def process_authentication(
    token_to_send: str, session: requests.Session, auth_method: str, hostname: str
) -> Tuple[str, int]:
    """
    Process authentication by sending a token and getting a response.

    Args:
        token_to_send: Authentication token to send
        session: Requests session
        auth_method: Authentication method (e.g., "Negotiate")
        hostname: Target hostname

    Returns:
        Tuple containing the server token and status code
    """
    auth_header = f"{auth_method} {token_to_send}"
    response = send_http(hostname, session, auth_header)

    www_auth = response.headers.get("WWW-Authenticate")
    if not www_auth or "Negotiate" not in www_auth:
        raise Exception("expecting www-authentication header from server but not found")

    parts = www_auth.split(" ", 1)
    if len(parts) != 2:
        raise Exception("Invalid WWW-Authenticate header format")

    server_token = parts[1].strip()
    return server_token, response.status_code


def step_sspi(
    cred_handle, target_spn: str, token_input: Optional[str] = None
) -> Tuple[str, int]:
    """
    Perform a step in the SSPI authentication process.

    Args:
        ctx_handle: Credential handle
        target_spn: Service Principal Name
        token_input: Optional input token

    Returns:
        Tuple containing the output token and status code
    """
    # Prepare input buffer
    if token_input:
        token_input_bytes: bytes = base64.b64decode(token_input)
        in_buf = win32security.PySecBufferDescType()
        token_buf = win32security.PySecBufferType(
            len(token_input_bytes), sspicon.SECBUFFER_TOKEN
        )
        token_buf.Buffer = token_input_bytes
        in_buf.append(token_buf)
    else:
        in_buf = None

    # Output buffer
    out_buf = win32security.PySecBufferDescType()
    out_token_buf = win32security.PySecBufferType(0, sspicon.SECBUFFER_TOKEN)
    out_buf.append(out_token_buf)
    context = getattr(step_sspi, "context", None)  # Initialize security context
    result = win32security.InitializeSecurityContext(
        cred_handle,  # Credential
        context,  # Context
        target_spn,  # TargetName
        sspicon.ISC_REQ_CONFIDENTIALITY | sspicon.ISC_REQ_INTEGRITY,  # ContextReq
        sspicon.SECURITY_NATIVE_DREP,  # TargetDataRep
        in_buf,  # pInput
        None,  
        out_buf,  # pOutput
    )

    new_ctx, out_bufs, status, _ = result
    step_sspi.context = new_ctx

    for buf in out_bufs:
        if buf.type == win32security.SECBUFFER_TOKEN:
            return base64.b64encode(buf.Buffer).decode(), status

    return "", status


def main() -> None:
    """
    Main function that handles Kerberos authentication and encryption.
    """
    # kdc_url: str = os.environ["SSPI_KDC_URL"]  # Used for configuration
    hostname: str = os.environ["SSPI_WINRM_HOST"]
    username: str = os.environ["SSPI_WINRM_USER"]
    password: str = os.environ["SSPI_WINRM_PASS"]
    auth_method: str = os.environ["SSPI_WINRM_AUTH"]

    domain: str = username.split("@")[1] if "@" in username else ""
    user: str = username.split("@")[0]

    (cred_handle, time_type) = get_credentials(user, domain, password)
    session: requests.Session = requests.Session()
    input_token: str = ""

    while True:
        print(f"step input token: {input_token}")
        output_token: str
        status: int
        output_token, status = step_sspi(
            cred_handle=cred_handle,
            target_spn=f"HTTP/{hostname}",
            token_input=input_token,
        )
        print(f"step result: {output_token[:30]}..., status: {status}")

        if status in [0, 0x90312]:  # SEC_E_OK or SEC_I_CONTINUE_NEEDED
            server_token: str
            status_code: int
            server_token, status_code = process_authentication(
                output_token, session, auth_method, hostname
            )

            if status == 0:  # SEC_E_OK
                print(f"Authentication completed successfully: {server_token[:30]}...")
                break
            input_token = server_token
        else:
            raise RuntimeError("Problem continuing authentication")

    # Encryption phase (simulating encrypting ./soap.xml)
    if not hasattr(step_sspi, "ctx_data"):
        raise RuntimeError("Security context missing for encryption")

    xml_data: bytes = Path("./soap.xml").read_bytes()
    trailer_size: int = win32security.QueryContextAttributes(
        step_sspi.ctx_data, sspicon.SECPKG_ATTR_SIZES
    )["SecurityTrailer"]
    token: bytearray = bytearray(trailer_size)

    sec_buffers = win32security.PySecBufferDescType()
    sec_buffers.append(
        win32security.PySecBufferType(len(xml_data), win32security.SECBUFFER_DATA)
    )
    sec_buffers[-1].Buffer = xml_data
    sec_buffers.append(
        win32security.PySecBufferType(len(token), win32security.SECBUFFER_TOKEN)
    )

    win32security.EncryptMessage(step_sspi.ctx_data, 0, sec_buffers, 0)
    print("Encrypting message complete")


if __name__ == "__main__":
    main()
