use super::{CipherSuite, Error, Opaque, ProtocolVersion, Vector};

use enum_try_from::impl_enum_try_from;
use nom::{
    bytes::complete::take,
    number::complete::{be_u16, be_u32, be_u8},
    IResult,
};
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

impl Random {
    pub fn deserialize(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, gmt_unix_time) = be_u32(input)?;
        let (input, random_bytes) = take(28u8)(input)?;

        Ok((
            input,
            Random {
                gmt_unix_time,
                random_bytes: random_bytes.try_into().unwrap(),
            },
        ))
    }
}

pub type CipherSuites = Vector<u16, CipherSuite>;
pub type CompressionMethods = Vector<u8, CompressionMethod>;
pub type Extensions = Vector<u16, Extension>;

#[derive(Serialize, Debug)]
pub struct Extension {
    pub extension_type: ExtensionType,
    pub data: Vector<u16, ExtensionData>,
}

#[derive(Serialize, Debug)]
pub struct SignatureAndHashAlgorithm {
    pub hash: HashAlgorithm,
    pub signature: SignatureAlgorithm,
}

//=============================================================================
// ServerHello
//=============================================================================

#[derive(Serialize, Debug)]
pub struct ServerHello {
    pub protocol_version: ProtocolVersion,
    pub random: Random,
    pub session_id: Opaque<u8>,
    pub cipher_suite: CipherSuite,
    pub compression_method: CompressionMethod,
    pub extensions: Extensions,
}

impl ServerHello {
    pub fn deserialize(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, protocol_version) = ProtocolVersion::deserialize(input)?;
        let (input, random) = Random::deserialize(input)?;
        let (input, session_id) = Opaque::<u8>::deserialize(input)?;
        let (input, cipher_suite) = CipherSuite::deserialize(input)?;
        let (input, compression_method) = CompressionMethod::deserialize(input)?;
        let extensions = Extensions {
            length: 0,
            data: vec![],
        };

        Ok((
            input,
            ServerHello {
                protocol_version,
                random,
                session_id,
                cipher_suite,
                compression_method,
                extensions,
            },
        ))
    }
}

//=============================================================================
// Enums
//=============================================================================
impl_enum_try_from! {
    #[repr(u8)]
    #[derive(Serialize_repr, Debug)]
    pub enum CompressionMethod {
        Null = 0,
    },
    u8,
    Error,
    Error::InvalidValue
}

impl CompressionMethod {
    pub fn deserialize(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, compression_method) = be_u8(input)?;
        let compression_metthod = CompressionMethod::try_from(compression_method).unwrap();
        Ok((input, compression_metthod))
    }
}

impl_enum_try_from! {
    #[repr(u16)]
    #[derive(Serialize_repr, Debug)]
    pub enum ExtensionType {
        SignatureAlgorithms = 13,
    },
    u16,
    Error,
    Error::InvalidValue
}

#[derive(Serialize, Debug)]
pub enum ExtensionData {
    SignatureAlgorithms(Vector<u16, SignatureAndHashAlgorithm>),
}

impl_enum_try_from! {
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
    },
    u8,
    Error,
    Error::InvalidValue
}

impl_enum_try_from! {
    #[allow(dead_code, clippy::upper_case_acronyms)]
    #[repr(u8)]
    #[derive(Serialize_repr, Debug)]
    pub enum SignatureAlgorithm {
        Anonymous = 0,
        RSA = 1,
        DSA = 2,
        ECDSA = 3,
    },
    u8,
    Error,
    Error::InvalidValue

}
