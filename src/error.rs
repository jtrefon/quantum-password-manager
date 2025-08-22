use thiserror::Error;

#[derive(Debug, Error)]
pub enum SecurityError {
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),
    
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),
    
    #[error("HMAC verification failed")]
    HmacVerificationFailed,
    
    #[error("Key derivation failed: {0}")]
    KeyDerivationFailed(String),
    
    #[error("Integrity check failed")]
    IntegrityCheckFailed,
    
    #[error("Invalid cryptographic parameters: {0}")]
    InvalidParameters(String),
    
    #[error("Unsupported security level")]
    UnsupportedSecurityLevel,
}