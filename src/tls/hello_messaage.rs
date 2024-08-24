use super::{ChiperSuite, Opaque, ProtocolVersion, Vector};

use serde::Serialize;
use serde_repr::Serialize_repr;

#[derive(Serialize, Debug)]
pub struct ClientHello {
    pub protocol_version: ProtocolVersion,
    pub random: Random,
    pub session_id: Opaque<u8>,
    pub chipher_suites: CipherSuites,
    pub compression_methods: CompressionMethods,
    pub extensions: Extensions,
}

#[derive(Serialize, Debug)]
pub struct Random {
    pub gmt_unix_time: u32,
    pub random_bytes: [u8; 28],
}

pub type CipherSuites = Vector<u16, ChiperSuite>;
pub type CompressionMethods = Vector<u8, CompressionMethod>;
pub type Extensions = Vector<u16, Extension>;

#[repr(u8)]
#[derive(Serialize_repr, Debug)]
pub enum CompressionMethod {
    Null = 0,
}

#[derive(Serialize, Debug)]
pub struct Extension {
    pub extension_type: ExtensionType,
    pub data: Vector<u16, ExtensionData>,
}

#[repr(u16)]
#[derive(Serialize_repr, Debug)]
pub enum ExtensionType {
    SignatureAlgorithms = 13,
}

#[derive(Serialize, Debug)]
pub enum ExtensionData {
    SignatureAlgorithms(Vector<u16, SignatureAndHashAlgorithm>),
}

#[derive(Serialize, Debug)]
pub struct SignatureAndHashAlgorithm {
    pub hash: HashAlgorithm,
    pub signature: SignatureAlgorithm,
}

#[allow(dead_code, clippy::upper_case_acronyms)]
#[repr(u8)]
#[derive(Serialize_repr, Debug)]
pub enum HashAlgorithm {
    None = 0,
    MD5 = 1,
    SHA1 = 2,
    SHA224 = 3,
    SHA256 = 4,
    SHA384 = 5,
    SHA512 = 6,
}

#[allow(dead_code, clippy::upper_case_acronyms)]
#[repr(u8)]
#[derive(Serialize_repr, Debug)]
pub enum SignatureAlgorithm {
    Anonymous = 0,
    RSA = 1,
    DSA = 2,
    ECDSA = 3,
}
