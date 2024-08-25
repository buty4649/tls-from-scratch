mod handshake;
mod hello_messaage;

pub use handshake::*;
pub use hello_messaage::*;

use nom::{
    bytes::complete::take,
    number::complete::{be_u16, be_u8},
    IResult,
};
use serde::Serialize;
use serde_repr::{Deserialize_repr, Serialize_repr};

use enum_try_from::impl_enum_try_from;

pub fn deserialize_tls_record(input: &[u8]) -> TLSRecord {
    let (_, record) = TLSRecord::deserialize(input).unwrap();
    record
}

#[repr(C)]
#[derive(Serialize, Debug)]
pub struct TLSRecord {
    pub content_type: ContentType,
    pub protocol_version: ProtocolVersion,
    pub length: u16,
    pub fragment: Handshake,
}

impl TLSRecord {
    pub fn deserialize(input: &[u8]) -> IResult<&[u8], TLSRecord> {
        let (input, content_type) = ContentType::deserialize(input)?;
        let (input, protocol_version) = ProtocolVersion::deserialize(input)?;
        let (input, length) = be_u16(input)?;
        let fragment = Handshake::deserialize(input).unwrap().1;

        Ok((
            input,
            TLSRecord {
                content_type,
                protocol_version,
                length,
                fragment,
            },
        ))
    }
}

#[derive(Debug)]
pub enum Error {
    InvalidValue,
}

#[derive(Serialize, Debug)]
pub struct Vector<T, D> {
    pub length: T,
    pub data: Vec<D>,
}

pub type Opaque<S> = Vector<S, u8>;

impl Opaque<u8> {
    pub fn deserialize(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, length) = be_u8(input)?;
        let (input, data) = take(length)(input)?;
        Ok((
            input,
            Vector {
                length,
                data: data.to_vec(),
            },
        ))
    }
}

impl_enum_try_from! {
    #[allow(dead_code)]
    #[repr(u16)]
    #[derive(Serialize_repr, Deserialize_repr, Debug)]
    pub enum ProtocolVersion {
        SSLv3 = 0x0300,
        TLSv1 = 0x0301,
        TLSv1_1 = 0x0302,
        TLSv1_2 = 0x0303,
        TLSv1_3 = 0x0304,
    },
    u16,
    Error,
    Error::InvalidValue
}

impl ProtocolVersion {
    pub fn deserialize(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, version) = be_u16(input)?;
        let version = ProtocolVersion::try_from(version).unwrap();
        Ok((input, version))
    }
}

impl_enum_try_from! {
    #[allow(dead_code)]
    #[repr(u8)]
    #[derive(Serialize_repr, Debug)]
    pub enum ContentType {
        ChangeCipherSpec = 20,
        Alert = 21,
        Handshake = 22,
        ApplicationData = 23,
    },
    u8,
    Error,
    Error::InvalidValue
}

impl ContentType {
    pub fn deserialize(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, content_type) = be_u8(input)?;
        let content_type = ContentType::try_from(content_type).unwrap();
        Ok((input, content_type))
    }
}

impl_enum_try_from! {
    #[allow(non_camel_case_types)]
    #[repr(u16)]
    #[derive(Serialize_repr, Debug)]
    pub enum CipherSuite {
        TLS_NULL_WITH_NULL_NULL = 0x0000,
        TLS_RSA_WITH_NULL_MD5 = 0x0001,
        TLS_RSA_WITH_NULL_SHA = 0x0002,
        TLS_RSA_WITH_RC4_128_MD5 = 0x0004,
        TLS_RSA_WITH_RC4_128_SHA = 0x0005,
        TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA = 0x000D,
        TLS_RSA_WITH_3DES_EDE_CBC_SHA = 0x000A,
        TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA = 0x0010,
        TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA = 0x0013,
        TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA = 0x0016,
        TLS_DH_anon_WITH_RC4_128_MD5 = 0x0018,
        TLS_DH_anon_WITH_3DES_EDE_CBC_SHA = 0x001B,
        TLS_RSA_WITH_AES_128_CBC_SHA = 0x002F,
        TLS_DH_DSS_WITH_AES_128_CBC_SHA = 0x0030,
        TLS_DH_RSA_WITH_AES_128_CBC_SHA = 0x0031,
        TLS_DHE_DSS_WITH_AES_128_CBC_SHA = 0x0032,
        TLS_DHE_RSA_WITH_AES_128_CBC_SHA = 0x0033,
        TLS_DH_anon_WITH_AES_128_CBC_SHA = 0x0034,
        TLS_RSA_WITH_AES_256_CBC_SHA = 0x0035,
        TLS_DH_DSS_WITH_AES_256_CBC_SHA = 0x0036,
        TLS_DH_RSA_WITH_AES_256_CBC_SHA = 0x0037,
        TLS_DHE_DSS_WITH_AES_256_CBC_SHA = 0x0038,
        TLS_DHE_RSA_WITH_AES_256_CBC_SHA = 0x0039,
        TLS_DH_anon_WITH_AES_256_CBC_SHA = 0x003A,
        TLS_RSA_WITH_NULL_SHA256 = 0x003B,
        TLS_RSA_WITH_AES_128_CBC_SHA256 = 0x003C,
        TLS_RSA_WITH_AES_256_CBC_SHA256 = 0x003D,
        TLS_DH_DSS_WITH_AES_128_CBC_SHA256 = 0x003E,
        TLS_DH_RSA_WITH_AES_128_CBC_SHA256 = 0x003F,
        TLS_DHE_DSS_WITH_AES_128_CBC_SHA256 = 0x0040,
        TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 = 0x0067,
        TLS_DH_DSS_WITH_AES_256_CBC_SHA256 = 0x0068,
        TLS_DH_RSA_WITH_AES_256_CBC_SHA256 = 0x0069,
        TLS_DHE_DSS_WITH_AES_256_CBC_SHA256 = 0x006A,
        TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 = 0x006B,
        TLS_DH_anon_WITH_AES_128_CBC_SHA256 = 0x006C,
        TLS_DH_anon_WITH_AES_256_CBC_SHA256 = 0x006D,
        TLS_RSA_WITH_AES_128_GCM_SHA256 = 0x009C,
        TLS_AES_128_GCM_SHA256 = 0x1301,
        TLS_AES_256_GCM_SHA384 = 0x1302,
        TLS_CHACHA20_POLY1305_SHA256 = 0x1303,
        TLS_AES_128_CCM_SHA256 = 0x1304,
        TLS_AES_128_CCM_8_SHA256 = 0x1305,
    },
    u16,
    Error,
    Error::InvalidValue
}

impl CipherSuite {
    pub fn deserialize(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, suite) = be_u16(input)?;
        let suite = CipherSuite::try_from(suite).unwrap();
        Ok((input, suite))
    }
}
