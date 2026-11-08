use std::string::FromUtf8Error;

use base64::prelude::*;
use rsa::signature::SignatureEncoding;
use rsa::traits::SignatureScheme;
use rsa::{
    Pkcs1v15Sign, RsaPublicKey,
    pkcs8::DecodePublicKey,
    sha2::{Digest, Sha512},
};

const PUBKEY: &str = "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0CGvmv+fltzgJfW4g32Q
bbxQzI76Ou+s8DKyNNUPlBRnahCMDaMtF7NwdRiU98nSHaClTk0WXRw3iTBGSdg3
1Xvej5Kh26i8g0FHfBNXTP8BuIqAGgcnw7kYhAY+wOA/JMmNf3ncCn7Hqea6CJ9+
kUFXnpF1C7N5XrFxJWKR5UstrOh3jBleoUdYxNO1J/6FegtGYzJXUgM0CiuPrzqW
w4+YkX59mhkv8+wHuiGt1BD/nUdWqLIXKeH/Az4sjJFJftbDefPvBNZs/yLg86PA
+TIIccbADK7iGFuF0MupitQKzYBx5KKvNBSj4fdFDyyNtpIxh3XzSixCODkCVa5c
6wIDAQAB
-----END PUBLIC KEY-----
";

#[derive(Debug)]
pub enum Error {
    RsaPublicKeyError(rsa::pkcs8::spki::Error),
    BadPublicKeyUtf8EncodingError(FromUtf8Error),
    BadPublicKeyBase64EncodingError(base64::DecodeError),
    RsaSignatureFileError(rsa::signature::Error),
    BadSignature(rsa::Error),
    Unknown,
}
impl std::error::Error for Error {}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}

impl From<rsa::pkcs8::spki::Error> for Error {
    fn from(err: rsa::pkcs8::spki::Error) -> Error {
        Error::RsaPublicKeyError(err)
    }
}

impl From<rsa::Error> for Error {
    fn from(err: rsa::Error) -> Error {
        Error::BadSignature(err)
    }
}

impl From<rsa::signature::Error> for Error {
    fn from(err: rsa::signature::Error) -> Error {
        Error::RsaSignatureFileError(err)
    }
}

impl From<FromUtf8Error> for Error {
    fn from(err: FromUtf8Error) -> Error {
        Error::BadPublicKeyUtf8EncodingError(err)
    }
}

impl From<base64::DecodeError> for Error {
    fn from(err: base64::DecodeError) -> Error {
        Error::BadPublicKeyBase64EncodingError(err)
    }
}

fn verify_signature(image_buf: &Vec<u8>, sig_buf: &[u8], pubkey: &str) -> Result<(), Error> {
    assert!(!pubkey.is_empty());
    println!("b64 decode and such: {}", pubkey);
    let b64 = BASE64_STANDARD.decode(pubkey.trim())?;
    println!("utf decode and such {:?}", b64);
    let utf8 = String::from_utf8(b64)?;
    println!("rsa public key decode and such");
    println!("{}", utf8);
    let key = rsa::RsaPublicKey::from_public_key_pem(&utf8)?;
    println!("do rest of verify");
    let signature = rsa::pkcs1v15::Signature::try_from(sig_buf)?;
    let scheme = Pkcs1v15Sign::new::<Sha512>();
    let hash = Sha512::digest(image_buf);
    key.verify(scheme, &hash, signature.to_bytes().as_ref())?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::process::Command;

    #[test]
    fn test_verify_signature() -> Result<(), anyhow::Error> {
        let image_buf: Vec<u8> = fs::read("./src/testimage")?;
        let sig_buf = fs::read("./src/testimage.sig")?;
        verify_signature(&image_buf, &sig_buf, &BASE64_STANDARD.encode(PUBKEY))?;
        Ok(())
    }

    #[test]
    fn test_verify_signature_from_cli_base64() -> Result<(), anyhow::Error> {
        // MUST USE --wrap=0 or the base64 crate will choke on the newlines and blow the stack
        let res = Command::new("base64")
            .arg("--wrap=0")
            .arg("./testpub.pem")
            .output()?;
        let pubkey_base64 = String::from_utf8(res.stdout)?;

        let image_buf: Vec<u8> = fs::read("./src/testimage")?;
        let sig_buf = fs::read("./src/testimage.sig")?;
        println!("call verify");
        verify_signature(&image_buf, &sig_buf, &pubkey_base64)?;
        Ok(())
    }
}
