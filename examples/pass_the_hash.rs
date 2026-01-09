//! This example demonstrates how to use pass-the-hash authentication with NTLM
//!
//! Pass-the-hash (PTH) allows you to authenticate using the NT hash of a password
//! instead of the password itself. This is useful in scenarios where you have
//! obtained the hash but not the plaintext password.
//!
//! Usage:
//! ```bash
//! cargo run --example pass_the_hash -- <username> <domain> <nt_hash>
//! ```
//!
//! The NT hash should be a 32-character hexadecimal string (16 bytes).

use sspi::{AuthIdentityBuffers, NtlmHash};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse command line arguments
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        eprintln!("Usage: {} <username> <domain> <nt_hash>", args[0]);
        eprintln!("\nExample:");
        eprintln!("  {} Administrator CONTOSO 32ed87bdb5fdc5e9cba88547376818d4", args[0]);
        std::process::exit(1);
    }

    let username = &args[1];
    let domain = &args[2];
    let nt_hash_str = &args[3];

    // Parse the NT hash from hex string
    let nt_hash: NtlmHash = nt_hash_str
        .as_str()
        .try_into()
        .map_err(|e| format!("Invalid NT hash: {}", e))?;

    println!("=== Pass-the-Hash NTLM Authentication Example ===");
    println!("Username: {}", username);
    println!("Domain: {}", domain);
    println!("NT Hash: {}", nt_hash_str);
    println!();

    // Create credentials using the NT hash instead of a password
    let credentials_with_hash = AuthIdentityBuffers::from_utf8_with_hash(username, domain, *nt_hash.as_bytes());

    println!("✓ Created AuthIdentityBuffers with NT hash");
    println!("  - Credential type: {:?}", credentials_with_hash.credential_type());
    println!("  - Is NT hash: {}", credentials_with_hash.credential_type().is_ntlm_hash());
    println!("  - Is password: {}", credentials_with_hash.credential_type().is_password());
    println!();

    // Compare with password-based credentials
    let credentials_with_password = AuthIdentityBuffers::from_utf8(username, domain, "SomePassword");

    println!("For comparison, password-based credentials:");
    println!("  - Credential type: {:?}", credentials_with_password.credential_type());
    println!("  - Is NT hash: {}", credentials_with_password.credential_type().is_ntlm_hash());
    println!("  - Is password: {}", credentials_with_password.credential_type().is_password());
    println!();

    // In a real NTLM authentication scenario:
    // 1. Create Ntlm instance with hash-based credentials
    // 2. The library will automatically use the NT hash in NTLMv2 calculations
    // 3. No password hashing is needed - the hash is used directly
    
    println!("=== How Pass-the-Hash Works ===");
    println!("1. Instead of hashing a password, the NT hash is used directly");
    println!("2. The NT hash is the MD4 hash of the UTF-16LE encoded password");
    println!("3. NTLMv2 authentication derives the NTLMv2 hash from the NT hash:");
    println!("   NTLMv2_hash = HMAC-MD5(NT_hash, uppercase(username) + domain)");
    println!("4. The authentication process then continues as normal");
    println!();
    
    println!("=== Integration with sspi-rs ===");
    println!("To use pass-the-hash in your application:");
    println!();
    println!("  let nt_hash: NtlmHash = \"32ed87bdb5fdc5e9cba88547376818d4\".try_into()?;");
    println!("  let credentials = AuthIdentityBuffers::from_utf8_with_hash(");
    println!("      \"username\",");
    println!("      \"DOMAIN\",");
    println!("      *nt_hash.as_bytes()");
    println!("  );");
    println!();
    println!("  let mut ntlm = Ntlm::with_auth_identity(Some(credentials), Default::default());");
    println!("  // Continue with normal NTLM authentication flow...");

    Ok(())
}
