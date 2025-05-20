// filepath: c:\\dev\\sspi-rs\\examples\\kerberos-win.rs
// Mimics the kerberos.rs example but uses the raw Windows API (via windows-rs)

use std::error::Error;
use std::ffi::c_void;
use std::io::{Read, Write}; // Added for TcpStream
use std::net::{Shutdown, TcpStream}; // Added for TcpStream
use std::ptr::{null, null_mut};
use std::collections::HashMap; // Added for parsing headers

use base64::Engine;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, EnvFilter};
use windows::core::{w, Error as WinError, PWSTR};


// RAII wrappers for handles to ensure cleanup
struct CredHandle(SEC_CREDENTIALS_HANDLE);
impl Drop for CredHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe { FreeCredentialsHandle(&self.0) };
        }
    }
}

struct CtxtHandle(SEC_CONTEXT_HANDLE);
impl Drop for CtxtHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe { DeleteSecurityContext(&self.0) };
        }
    }
}

fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let hostname = std::env::var("SSPI_WINRM_HOST").expect("missing host name set in SSPI_WINRM_HOST"); // winrm_server_name.domain
    let username = std::env::var("SSPI_WINRM_USER").ok(); // Optional: username@domain or user
    let password = std::env::var("SSPI_WINRM_PASS").ok(); // Optional: password
    let auth_method_name = std::env::var("SSPI_WINRM_AUTH").unwrap_or_else(|_| "Negotiate".to_string()); // Negotiate or Kerberos

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_env("SSPI_LOG_LEVEL"))
        .init();

    let auth_package = if auth_method_name.eq_ignore_ascii_case("Kerberos") {
        MICROSOFT_KERBEROS_NAME_W // Use w!("Kerberos")
    } else {
        NEGOSSP_NAME_W // Use w!("Negotiate")
    };

    let mut cred_handle = get_cred_handle(auth_package, username, password)?;
    let mut ctxt_handle: Option<CtxtHandle> = None; // Will be initialized in the first step

    let mut input_token_b64 = String::new();
    let mut stream_opt: Option<TcpStream> = None; // Use Option<TcpStream> for keep-alive

    let target_spn = make_spn("HTTP", &hostname)?;
    tracing::info!(?target_spn, "Generated SPN");

    loop {
        tracing::info!(input_token_len = input_token_b64.len(), "Loop start");

        let (output_token_b64, status, new_ctxt_handle) = step(
            &mut cred_handle.0,
            ctxt_handle.as_ref().map(|h| &h.0),
            &input_token_b64,
            &target_spn,
        )?;

        if let Some(new_handle) = new_ctxt_handle {
            ctxt_handle = Some(new_handle); // Store the context handle
        }

        tracing::info!(output_token_len = output_token_b64.len(), ?status, "Step result");

        if status == SEC_I_CONTINUE_NEEDED || status == SEC_E_OK {
            // Pass the stream option to process_authentication
            let (token_from_server_b64, status_code, updated_stream_opt) =
                process_authentication(&output_token_b64, &mut stream_opt, &auth_method_name, &hostname)?;
            stream_opt = updated_stream_opt; // Update the stream for keep-alive

            if status == SEC_E_OK {
                tracing::info!(?token_from_server_b64, ?status_code, "Authentication completed successfully");
                break;
            }

            input_token_b64 = token_from_server_b64;
        } else {
            // Map the SECURITY_STATUS to a Windows Error
            let win_error = WinError::from_win32();
            tracing::error!(?status, ?win_error, "Authentication failed");
            return Err(format!("Authentication failed with status: {:?} ({})", status, win_error).into());
        }
    }

    // --- Authentication successful, context handle is in ctxt_handle ---
    let final_ctxt_handle = ctxt_handle.expect("Context handle should exist after successful auth");
    tracing::info!("Authentication successful!");

    // Example: Encrypt a message (optional)
    // Ensure soap.xml exists in the examples directory or adjust path
    // let mut request_body = std::fs::read("./examples/soap.xml")?;
    // encrypt_and_send(&final_ctxt_handle.0, &mut request_body, &hostname, &mut stream_opt)?;

    // Close the connection if it's still open
    if let Some(mut stream) = stream_opt {
        let _ = stream.shutdown(Shutdown::Both);
    }

    Ok(())
}

// Helper to create SEC_WINNT_AUTH_IDENTITY_W (wide-char version)
fn create_auth_identity(
    username: Option<String>,
    password: Option<String>,
) -> Option<SEC_WINNT_AUTH_IDENTITY_W> {
    match (username, password) {
        (Some(u), Some(p)) => {
            // IMPORTANT: These Vecs must live as long as the SEC_WINNT_AUTH_IDENTITY_W struct
            // For simplicity here, we leak them or manage them carefully.
            // A safer approach involves a dedicated struct.
            // This example uses a simplified approach; real code needs careful lifetime management.
            let (user_utf16, domain_utf16) = match u.split_once('@') {
                 Some((user, domain)) => (
                    user.encode_utf16().chain(std::iter::once(0)).collect::<Vec<u16>>(),
                    domain.encode_utf16().chain(std::iter::once(0)).collect::<Vec<u16>>(),
                 ),
                 None => ( // Assume username only, no domain
                    u.encode_utf16().chain(std::iter::once(0)).collect::<Vec<u16>>(),
                    Vec::new(), // No domain
                 )
            };
            let password_utf16 = p.encode_utf16().chain(std::iter::once(0)).collect::<Vec<u16>>();

            // Leak the vectors to ensure they live long enough for the API call.
            // WARNING: This leaks memory. Proper management is needed in production code.
            let user_ptr = Box::leak(user_utf16.into_boxed_slice()).as_mut_ptr();
            let domain_ptr = if domain_utf16.is_empty() { null_mut() } else { Box::leak(domain_utf16.into_boxed_slice()).as_mut_ptr() };
            let password_ptr = Box::leak(password_utf16.into_boxed_slice()).as_mut_ptr();


            Some(SEC_WINNT_AUTH_IDENTITY_W {
                User: PWSTR(user_ptr),
                UserLength: (user_utf16.len() -1) as u32, // Exclude null terminator
                Domain: PWSTR(domain_ptr),
                DomainLength: if domain_utf16.is_empty() { 0 } else { (domain_utf16.len() - 1) as u32 }, // Exclude null terminator
                Password: PWSTR(password_ptr),
                PasswordLength: (password_utf16.len() - 1) as u32, // Exclude null terminator
                Flags: SEC_WINNT_AUTH_IDENTITY_FLAGS::SEC_WINNT_AUTH_IDENTITY_UNICODE.0, // Use Unicode
            })
        }
        _ => None, // Use default credentials (logged-on user)
    }
}

fn get_cred_handle(
    auth_package: PWSTR,
    username: Option<String>,
    password: Option<String>,
) -> Result<CredHandle, Box<dyn Error + Send + Sync>> {
    let mut handle = SEC_CREDENTIALS_HANDLE::default();
    let mut expiry = 0i64; // FILETIME

    // Prepare auth identity if username/password are provided
    let mut auth_identity_opt = create_auth_identity(username, password);
    let p_auth_data: *mut c_void = match &mut auth_identity_opt {
        Some(identity) => identity as *mut _ as *mut c_void,
        None => null_mut(), // Use logged-on user credentials
    };

    let status = unsafe {
        AcquireCredentialsHandleW(
            None,           // Principal name (None for logged-on user)
            auth_package,   // Package name (e.g., "Negotiate" or "Kerberos")
            SECPKG_CRED_OUTBOUND, // Credential use
            None,           // Logon ID (None for current process)
            p_auth_data,    // Auth data (username/password or None)
            None,           // Get key function
            None,           // Get key argument
            &mut handle,    // Credential handle (output)
            Some(&mut expiry), // Expiry time (output)
        )
    };

    // IMPORTANT: Clean up leaked memory if auth_identity_opt was Some.
    // This requires careful handling in real code, perhaps using scope guards or dedicated structs.
    // The current simplified version leaks memory.

    if status != SEC_E_OK {
        return Err(format!("AcquireCredentialsHandleW failed: {:?}", WinError::from_win32()).into());
    }

    tracing::info!(?handle, "Acquired credential handle");
    Ok(CredHandle(handle))
}

fn make_spn(service_class: &str, instance_name: &str) -> Result<String, Box<dyn Error + Send + Sync>> {
    let service_class_w = service_class.encode_utf16().collect::<Vec<_>>();
    let instance_name_w = instance_name.encode_utf16().collect::<Vec<_>>();
    let mut spn_len = 0u32;

    // First call to get the required buffer size
    let status = unsafe {
        SecMakeSPN(
            service_class_w.as_ptr(),
            instance_name_w.as_ptr(),
            None, // Optional instance name, already included in instance_name
            0,    // Optional instance port
            None, // Optional referrer
            &mut spn_len,
            None, // Buffer (null on first call)
        )
    };

    // Expecting ERROR_INSUFFICIENT_BUFFER or similar if successful pre-check
    if spn_len == 0 {
        return Err(format!("SecMakeSPN failed to get length: {:?}", WinError::from_win32()).into());
    }

    let mut spn_buffer: Vec<u16> = vec![0; spn_len as usize];

    // Second call to actually create the SPN
    let status = unsafe {
        SecMakeSPN(
            service_class_w.as_ptr(),
            instance_name_w.as_ptr(),
            None,
            0,
            None,
            &mut spn_len,
            Some(spn_buffer.as_mut_ptr()),
        )
    };

    if status != SEC_E_OK {
        return Err(format!("SecMakeSPN failed: {:?}", WinError::from_win32()).into());
    }

    // Convert wide string buffer to Rust String, removing potential null terminator
    Ok(String::from_utf16_lossy(&spn_buffer[..spn_len as usize]))
}


fn step(
    cred_handle: &SEC_CREDENTIALS_HANDLE,
    ctxt_handle_opt: Option<&SEC_CONTEXT_HANDLE>, // Use existing context if available
    input_token_b64: &str,
    target_name: &str, // SPN
) -> Result<(String, SECURITY_STATUS, Option<CtxtHandle>), Box<dyn Error + Send + Sync>> {

    let input_bytes = base64::engine::general_purpose::STANDARD.decode(input_token_b64)?;
    tracing::debug!(input_bytes_len = input_bytes.len(), "Decoded input token");

    let mut input_sec_buffer = SecurityBuffer {
        cbBuffer: input_bytes.len() as u32,
        BufferType: SECBUFFER_TOKEN.0, // Input token
        pvBuffer: if input_bytes.is_empty() {
            null_mut()
        } else {
            input_bytes.as_ptr() as *mut c_void
        },
    };
    let mut input_desc = SecurityBufferDesc {
        ulVersion: 0, // SECBUFFER_VERSION
        cBuffers: 1,
        pBuffers: &mut input_sec_buffer,
    };
    let p_input = if input_bytes.is_empty() {
        None // No input token on the first call
    } else {
        Some(&input_desc)
    };

    // Prepare output buffer
    // Max token size can be queried, but a large buffer usually works.
    // See SecPkgInfoW and cbMaxToken.
    const MAX_TOKEN_SIZE: usize = 12288; // Adjust as needed
    let mut output_buffer_vec: Vec<u8> = vec![0; MAX_TOKEN_SIZE];
    let mut output_sec_buffer = SecurityBuffer {
        cbBuffer: output_buffer_vec.len() as u32,
        BufferType: SECBUFFER_TOKEN.0, // Output token
        pvBuffer: output_buffer_vec.as_mut_ptr() as *mut c_void,
    };
    let mut output_desc = SecurityBufferDesc {
        ulVersion: 0, // SECBUFFER_VERSION
        cBuffers: 1,
        pBuffers: &mut output_sec_buffer,
    };

    let mut new_ctxt_handle = SEC_CONTEXT_HANDLE::default();
    let mut context_attributes: u32 = 0;
    let mut expiry = 0i64; // FILETIME

    let target_name_w: Vec<u16> = target_name.encode_utf16().chain(std::iter::once(0)).collect();

    let status = unsafe {
        InitializeSecurityContextW(
            cred_handle,                        // Credential handle
            ctxt_handle_opt,                    // Existing context handle (if any)
            Some(PWSTR(target_name_w.as_ptr() as *mut _)), // Target name (SPN)
            ISC_REQ_STANDARD_FLAGS | ISC_REQ_CONFIDENTIALITY | ISC_REQ_INTEGRITY, // Context requirements
            0,                                  // Reserved1
            0, // Target data representation (not needed for Kerberos/Negotiate usually)
            p_input,                            // Input buffer descriptor
            0,                                  // Reserved2
            &mut new_ctxt_handle,               // New context handle (output/updated)
            Some(&mut output_desc),             // Output buffer descriptor
            &mut context_attributes,            // Context attributes (output)
            Some(&mut expiry),                  // Expiry time (output)
        )
    };

    tracing::debug!(?status, output_buffer_len = output_sec_buffer.cbBuffer, ?context_attributes, "InitializeSecurityContextW result");

    let output_token_b64 = if status == SEC_E_OK || status == SEC_I_CONTINUE_NEEDED {
        // Get the actual size of the token written
        let token_data = unsafe {
            std::slice::from_raw_parts(
                output_sec_buffer.pvBuffer as *const u8,
                output_sec_buffer.cbBuffer as usize,
            )
        };
        base64::engine::general_purpose::STANDARD.encode(token_data)
    } else {
        // Handle errors like SEC_E_INVALID_TOKEN, SEC_E_LOGON_DENIED, etc.
        tracing::error!("InitializeSecurityContextW failed: {:?}", WinError::from_win32());
        String::new() // No token generated on error
    };

    // Wrap the new handle only if it's the first successful call or continuation
    let returned_ctxt_handle = if (ctxt_handle_opt.is_none() || ctxt_handle_opt.unwrap().is_invalid())
                                  && !new_ctxt_handle.is_invalid()
                                  && (status == SEC_E_OK || status == SEC_I_CONTINUE_NEEDED)
    {
        Some(CtxtHandle(new_ctxt_handle))
    } else {
        None // Don't return a new wrapper if we already had a valid one or if the call failed
    };


    Ok((output_token_b64, status, returned_ctxt_handle))
}

// --- HTTP Helper Functions (Rewritten for std::net) ---

// Helper to parse HTTP status line
fn parse_status_line(line: &str) -> Result<u16, Box<dyn Error + Send + Sync>> {
    let parts: Vec<&str> = line.splitn(3, ' ').collect();
    if parts.len() < 2 {
        return Err("Invalid HTTP status line".into());
    }
    parts[1].parse::<u16>().map_err(|e| e.into())
}

// Helper to parse HTTP headers
fn parse_headers(header_lines: &[&str]) -> HashMap<String, String> {
    let mut headers = HashMap::new();
    for line in header_lines {
        if let Some((key, value)) = line.split_once(": ") {
            headers.insert(key.trim().to_lowercase(), value.trim().to_string());
        }
    }
    headers
}


fn process_authentication(
    token_to_send_b64: &str,
    stream_opt: &mut Option<TcpStream>, // Pass mutable Option<TcpStream>
    auth_method: &str, // "Negotiate" or "Kerberos"
    hostname: &str,
) -> Result<(String, u16, Option<TcpStream>), Box<dyn Error + Send + Sync>> { // Return updated stream
    let auth_header_value = format!("{} {}", auth_method, token_to_send_b64);

    // Send HTTP request using std::net::TcpStream
    let (status_code, headers, response_body, updated_stream) =
        send_http(hostname, stream_opt, Some(auth_header_value), None)?;

    // Check if authentication is complete or requires another step
    if status_code == 200 { // Check for 200 OK
        tracing::info!("HTTP 200 OK received, authentication likely successful.");
    } else if status_code != 401 { // Check for 401 Unauthorized
        // Close the stream on unexpected status
        if let Some(mut stream) = updated_stream {
             let _ = stream.shutdown(Shutdown::Both);
        }
        return Err(format!("Unexpected HTTP status code: {}", status_code).into());
    }

    // Extract the token from the WWW-Authenticate header
    let www_authenticate = headers
        .get("www-authenticate") // Headers are lowercased by parse_headers
        .ok_or("WWW-Authenticate header missing from server response")?;

    tracing::debug!(?www_authenticate, "Received WWW-Authenticate header");

    let server_token_b64 = match www_authenticate.split_once(' ') {
        Some((method, token)) if method.eq_ignore_ascii_case(auth_method) => token.trim().to_owned(),
        _ => {
             // Close the stream on error
            if let Some(mut stream) = updated_stream {
                 let _ = stream.shutdown(Shutdown::Both);
            }
            return Err(format!("Invalid or unexpected WWW-Authenticate header format: {}", www_authenticate).into())
        },
    };

    tracing::info!(server_token_len = server_token_b64.len(), ?status_code, "Extracted token from server");

    Ok((server_token_b64, status_code, updated_stream)) // Return the potentially updated stream
}


fn send_http(
    hostname: &str,
    stream_opt: &mut Option<TcpStream>, // Use mutable Option for keep-alive
    authorization: Option<String>,
    body: Option<Vec<u8>>,
) -> Result<(u16, HashMap<String, String>, Vec<u8>, Option<TcpStream>), Box<dyn Error + Send + Sync>> {
    let addr = format!("{}:5985", hostname); // Standard WinRM port

    // Establish connection if not already present or reuse existing one
    let mut stream = match stream_opt.take() { // Take ownership to potentially replace
        Some(s) => {
            tracing::debug!("Reusing existing TCP connection to {}", addr);
            s
        },
        None => {
            tracing::debug!("Establishing new TCP connection to {}", addr);
            TcpStream::connect(&addr)?
        }
    };
    stream.set_read_timeout(Some(std::time::Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(std::time::Duration::from_secs(10)))?;


    let body_len = body.as_ref().map_or(0, |b| b.len());
    let host_header = format!("{}:5985", hostname);

    // Construct HTTP request manually
    let mut request = format!("POST /wsman HTTP/1.1\r\n");
    request.push_str(&format!("Host: {}\r\n", host_header));
    request.push_str("Connection: Keep-Alive\r\n"); // Request keep-alive
    request.push_str("User-Agent: Rust-SSPI-Win-Client/1.0\r\n");
    request.push_str("Accept: */*\r\n");
    request.push_str("Accept-Encoding: identity\r\n");
    request.push_str("Accept-Language: en-US\r\n");
    if let Some(auth) = authorization {
        request.push_str(&format!("Authorization: {}\r\n", auth));
    }
    if body.is_some() {
         request.push_str("Content-Type: application/soap+xml;charset=UTF-8\r\n");
    }
    request.push_str(&format!("Content-Length: {}\r\n", body_len));
    request.push_str("\r\n"); // End of headers

    tracing::debug!(request_headers = ?request, "Sending HTTP Request Headers");

    // Write headers
    stream.write_all(request.as_bytes())?;

    // Write body if present
    if let Some(body_bytes) = &body {
        tracing::debug!(body_len = body_bytes.len(), "Sending HTTP Request Body");
        stream.write_all(body_bytes)?;
    }
    stream.flush()?; // Ensure request is sent

    // Read response
    let mut response_buf = Vec::new();
    let mut chunk = [0u8; 4096]; // Read in chunks
    let mut total_read = 0;
    let mut headers_parsed = false;
    let mut status_code = 0u16;
    let mut headers = HashMap::new();
    let mut response_body = Vec::new();
    let mut content_length = 0;

    loop {
        match stream.read(&mut chunk) {
            Ok(0) => {
                tracing::debug!("Connection closed by peer while reading response.");
                break; // Connection closed
            }
            Ok(n) => {
                response_buf.extend_from_slice(&chunk[..n]);
                total_read += n;
                tracing::trace!(bytes_read = n, total_bytes = total_read, "Read chunk from TCP stream");

                // Try parsing headers if not already done
                if !headers_parsed {
                    if let Some(header_end_idx) = response_buf.windows(4).position(|window| window == b"\r\n\r\n") {
                        let header_data = &response_buf[..header_end_idx];
                        let header_str = String::from_utf8_lossy(header_data);
                        let lines: Vec<&str> = header_str.lines().collect();

                        if lines.is_empty() {
                            return Err("Received empty response".into());
                        }

                        status_code = parse_status_line(lines[0])?;
                        headers = parse_headers(&lines[1..]);
                        headers_parsed = true;
                        tracing::debug!(?status_code, ?headers, "Parsed HTTP Response Headers");

                        // Get content length
                        if let Some(len_str) = headers.get("content-length") {
                            content_length = len_str.parse::<usize>().unwrap_or(0);
                        }

                        // Copy body part already read
                        response_body.extend_from_slice(&response_buf[header_end_idx + 4..]);
                    }
                } else {
                     // Append directly to body if headers are already parsed
                     response_body.extend_from_slice(&chunk[..n]);
                }

                // Check if we have read the complete body based on Content-Length
                if headers_parsed && response_body.len() >= content_length {
                     tracing::debug!(body_len = response_body.len(), expected_len = content_length, "Received expected content length");
                     break; // Got full body
                }

                 // Add a safety break if response gets too large without Content-Length or proper termination
                 const MAX_RESPONSE_SIZE: usize = 5 * 1024 * 1024; // 5MB limit
                 if total_read > MAX_RESPONSE_SIZE {
                     tracing::warn!("Response size exceeded limit, stopping read.");
                     // Attempt to return what was read, might be incomplete
                     break;
                 }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                tracing::trace!("Read would block, waiting...");
                // This shouldn't happen with blocking sockets, but handle defensively
                std::thread::sleep(std::time::Duration::from_millis(50));
                continue;
            }
            Err(e) => {
                tracing::error!("TCP read error: {}", e);
                 // Don't return the stream if there was a read error
                 return Err(e.into());
            }
        }
    }

    if !headers_parsed {
        return Err("Failed to parse HTTP headers (incomplete response?)".into());
    }

    // Decide whether to keep the stream alive
    let keep_alive = headers.get("connection")
                           .map_or(false, |v| v.eq_ignore_ascii_case("keep-alive"));

    let return_stream = if keep_alive {
        tracing::debug!("Keeping TCP connection alive.");
        Some(stream) // Return the stream to be reused
    } else {
        tracing::debug!("Closing TCP connection.");
        let _ = stream.shutdown(Shutdown::Both); // Explicitly close if not keep-alive
        None
    };

    Ok((status_code, headers, response_body, return_stream))
}


// --- Optional Encryption Example (Updated for std::net) ---

fn encrypt_and_send(
    ctxt_handle: &SEC_CONTEXT_HANDLE, // Corrected type
    data: &mut Vec<u8>,
    hostname: &str,
    stream_opt: &mut Option<TcpStream>, // Pass mutable Option<TcpStream>
) -> Result<(), Box<dyn Error + Send + Sync>> {
    tracing::info!("Attempting to encrypt message...");

    // Query context sizes for encryption buffers
    let mut sizes = SecPkgContext_Sizes::default();
    let status = unsafe { QueryContextAttributesW(ctxt_handle, SECPKG_ATTR_SIZES, &mut sizes as *mut _ as *mut c_void) };
    if status != SEC_E_OK {
        // Corrected formatting
        return Err(format!("QueryContextAttributesW(SECPKG_ATTR_SIZES) failed: {:?}", WinError::from_win32()).into());
    }
    tracing::debug!(?sizes, "Queried context sizes");

    // Prepare buffers for EncryptMessage
    let mut trailer_buf = vec![0u8; sizes.cbSecurityTrailer as usize];
    // data buffer is now passed as mutable, no need to clone unless modification is undesired
    let mut padding_buf = vec![0u8; sizes.cbBlockSize as usize]; // Optional padding buffer if needed

    let mut buffers = [
        SecurityBuffer { // Data buffer (will be encrypted in place)
            cbBuffer: data.len() as u32,
            BufferType: SECBUFFER_DATA.0,
            pvBuffer: data.as_mut_ptr() as *mut _,
        },
        SecurityBuffer { // Security trailer buffer
            cbBuffer: trailer_buf.len() as u32,
            BufferType: SECBUFFER_TOKEN.0, // Trailer is often treated as a token
            pvBuffer: trailer_buf.as_mut_ptr() as *mut _,
        },
         SecurityBuffer { // Padding buffer (optional, depends on algorithm/flags)
            cbBuffer: padding_buf.len() as u32,
            BufferType: SECBUFFER_PADDING.0, // Indicate padding
            pvBuffer: padding_buf.as_mut_ptr() as *mut _,
        },
        SecurityBuffer { // Empty buffer (marks end)
            cbBuffer: 0,
            BufferType: SECBUFFER_EMPTY.0,
            pvBuffer: null_mut(),
        },
    ];

    // Adjust buffer count based on whether padding is used (often not explicitly needed)
    let buffer_count = 2; // Typically data + trailer is sufficient for basic encryption

    let mut msg_desc = SecurityBufferDesc {
        ulVersion: 0, // SECBUFFER_VERSION
        cBuffers: buffer_count,
        pBuffers: buffers.as_mut_ptr(),
    };

    // Encrypt the message
    let encrypt_flags = 0; // Use default encryption, not SECQOP_WRAP_NO_ENCRYPT
    let mut seq_num = 0; // Sequence number for replay detection (start at 0)

    let status = unsafe { EncryptMessage(ctxt_handle, encrypt_flags, &mut msg_desc, seq_num) };

    if status != SEC_E_OK {
        // Corrected formatting
        return Err(format!("EncryptMessage failed: {:?}", WinError::from_win32()).into());
    }

    tracing::info!("Message encrypted successfully.");

    // Combine the encrypted data (now in `data`) and the security trailer into a single payload
    let encrypted_data_len = buffers[0].cbBuffer as usize; // Get actual length after encryption
    let trailer_data = unsafe { std::slice::from_raw_parts(buffers[1].pvBuffer as *const u8, buffers[1].cbBuffer as usize) };

    let mut http_body = Vec::with_capacity(encrypted_data_len + trailer_data.len());
    http_body.extend_from_slice(&data[..encrypted_data_len]); // Use the modified data buffer
    http_body.extend_from_slice(trailer_data);


    tracing::info!(body_len = http_body.len(), "Sending encrypted message");

    // Send the encrypted payload - NO Authorization header needed now, context handles session
    let (status_code, _headers, _response_body, updated_stream) =
        send_http(hostname, stream_opt, None, Some(http_body))?;

    *stream_opt = updated_stream; // Update the stream option in the caller

    if !(200..300).contains(&status_code) { // Check for 2xx success
        return Err(format!("HTTP request with encrypted body failed: {}", status_code).into());
    }

    tracing::info!("Encrypted request sent successfully, status: {}", status_code);

    // TODO: Decrypt the response using DecryptMessage if needed

    Ok(())
}

// Define SECBUFFER_PADDING if not available in windows-rs version
#[allow(non_upper_case_globals)]
const SECBUFFER_PADDING: windows::Win32::Security::Sspi::SECBUFFER_TYPE = windows::Win32::Security::Sspi::SECBUFFER_TYPE(3);

