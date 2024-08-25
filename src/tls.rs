mod de;
mod handshake;
mod hello_messaage;

use de::*;
pub use handshake::*;
pub use hello_messaage::*;

use serde::Serialize;
use serde_repr::{Deserialize_repr, Serialize_repr};

use enum_try_from::impl_enum_try_from;

pub fn deserialize_tls_record(input: &[u8], length: usize) -> Vec<TLSRecord> {
    let mut records = vec![];
    let mut buffer = Buffer::new(input, length);

    loop {
        if buffer.length() == 0 {
            break;
        }

        let (new_buffer, record) = TLSRecord::deserialize(buffer).unwrap();
        buffer = new_buffer;

        records.push(record);
    }

    records
}

#[repr(C)]
#[derive(Serialize, Debug)]
pub struct TLSRecord {
    pub content_type: ContentType,
    pub protocol_version: ProtocolVersion,
    pub length: u16,
    pub fragment: Fragment,
}

impl TLSRecord {
    pub fn deserialize(input: Buffer) -> IResult<TLSRecord> {
        let (input, content_type) = ContentType::deserialize(input)?;
        let (input, protocol_version) = ProtocolVersion::deserialize(input)?;
        let (input, length) = be_u16(input)?;

        let (input, fragment) = take(input, length)?;
        let fragment = Buffer::new(fragment, length as usize);
        let fragment = match content_type {
            ContentType::Handshake => {
                let (_, handshake) = Handshake::deserialize(fragment)?;
                Fragment::Handshake(handshake)
            }
            ContentType::ChangeCipherSpec => {
                let (_, spec) = ChangeCipherSpec::deserialize(fragment)?;
                Fragment::ChangeCipherSpec(spec)
            }
            ContentType::Alert => {
                let (_, alert) = Alert::deserialize(fragment)?;
                Fragment::Alert(alert)
            }
            _ => unimplemented!(),
        };

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

#[derive(Serialize, Debug)]
pub enum Fragment {
    Handshake(Handshake),
    ChangeCipherSpec(ChangeCipherSpec),
    Alert(Alert),
}

impl_enum_try_from! {
    #[repr(u8)]
    #[derive(Serialize_repr, Debug)]
    pub enum ChangeCipherSpec {
        ChangeCipherSpec = 1,
    },
    u8,
    Error,
    Error::InvalidValue
}

impl ChangeCipherSpec {
    pub fn deserialize(input: Buffer) -> IResult<Self> {
        let (input, spec) = be_u8(input)?;
        Ok((input, ChangeCipherSpec::try_from(spec).unwrap()))
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
    pub fn deserialize(input: Buffer) -> IResult<Self> {
        let (input, length) = be_u8(input)?;
        let (input, data) = take(input, length)?;
        Ok((
            input,
            Vector {
                length,
                data: data.to_vec(),
            },
        ))
    }
}

impl Opaque<u24> {
    pub fn deserialize(input: Buffer) -> IResult<Self> {
        let (input, length) = u24::deserialize(input)?;
        let (input, data) = take(input, length)?;
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
    pub fn deserialize(input: Buffer) -> IResult<Self> {
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
    pub fn deserialize(input: Buffer) -> IResult<Self> {
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
    pub fn deserialize(input: Buffer) -> IResult<Self> {
        let (input, suite) = be_u16(input)?;
        let suite = CipherSuite::try_from(suite).unwrap();
        Ok((input, suite))
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy)]
pub struct u24 {
    data: u32,
}

impl u24 {
    pub fn deserialize(input: Buffer) -> IResult<Self> {
        let (input, data) = take(input, 3u8)?;
        let data = u24::from(data);
        Ok((input, data))
    }

    pub fn to_u16(self) -> u16 {
        self.data as u16
    }

    pub fn to_usize(self) -> usize {
        self.data as usize
    }
}

impl Serialize for u24 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let bytes = [
            ((self.data >> 16) & 0xff) as u8,
            ((self.data >> 8) & 0xff) as u8,
            (self.data & 0xff) as u8,
        ];
        serializer.serialize_bytes(&bytes)
    }
}

impl From<u16> for u24 {
    fn from(value: u16) -> Self {
        u24 { data: value as u32 }
    }
}

impl From<u32> for u24 {
    fn from(value: u32) -> Self {
        u24 {
            data: value & 0xffffff,
        }
    }
}

impl From<usize> for u24 {
    fn from(value: usize) -> Self {
        u24 {
            data: value as u32 & 0xffffff,
        }
    }
}

impl From<&[u8]> for u24 {
    fn from(value: &[u8]) -> Self {
        let data = (value[0] as u32) << 16 | (value[1] as u32) << 8 | value[2] as u32;
        u24 { data }
    }
}

impl nom::ToUsize for u24 {
    fn to_usize(&self) -> usize {
        self.data as usize
    }
}

#[derive(Serialize, Debug)]
pub struct Alert {
    pub level: AlertLevel,
    pub description: AlertDescription,
}

impl Alert {
    pub fn deserialize(input: Buffer) -> IResult<Self> {
        let (input, level) = be_u8(input)?;
        let level = AlertLevel::try_from(level).unwrap();
        let (input, description) = be_u8(input)?;
        let description = AlertDescription::try_from(description).unwrap();
        Ok((input, Alert { level, description }))
    }
}

impl_enum_try_from! {
    #[allow(dead_code)]
    #[repr(u8)]
    #[derive(Serialize_repr, Debug)]
    pub enum AlertLevel {
        Warning = 1,
        Fatal = 2,
    },
    u8,
    Error,
    Error::InvalidValue
}

impl_enum_try_from! {
    #[allow(dead_code)]
    #[repr(u8)]
    #[derive(Serialize_repr, Debug)]
    pub enum AlertDescription {
        CloseNotify = 0,
        UnexpectedMessage = 10,
        BadRecordMac = 20,
        DecryptionFailedReserved = 21,
        RecordOverflow = 22,
        DecompressionFailureReserved = 30,
        HandshakeFailure = 40,
        NoCertificateReserved = 41,
        BadCertificate = 42,
        UnsupportedCertificate = 43,
        CertificateRevoked = 44,
        CertificateExpired = 45,
        CertificateUnknown = 46,
        IllegalParameter = 47,
        UnknownCa = 48,
        AccessDenied = 49,
        DecodeError = 50,
        DecryptError = 51,
        ExportRestrictionReserved = 60,
        ProtocolVersion = 70,
        InsufficientSecurity = 71,
        InternalError = 80,
        InappropriateFallback = 86,
        UserCanceled = 90,
        NoRenegotiationReserved = 100,
        MissingExtension = 109,
        UnsupportedExtension = 110,
        CertificateUnobtainableReserved = 111,
        UnrecognizedName = 112,
        BadCertificateStatusResponse = 113,
        BadCertificateHashValueReserved = 114,
        UnknownPskIdentity = 115,
        CertificateRequired = 116,
        NoApplicationProtocol = 120,
    },
    u8,
    Error,
    Error::InvalidValue
}
