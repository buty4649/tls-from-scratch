use super::hello_messaage::{ClientHello, ServerHello};
use super::{be_u8, take, u24, Buffer, Error, IResult, Opaque, ProtocolVersion};

use enum_try_from::impl_enum_try_from;
use ser::ByteOrder;
use serde::Serialize;
use serde_repr::Serialize_repr;

#[derive(Serialize, Debug)]
pub struct Handshake {
    pub msg_type: HandshakeType,
    pub length: u24,
    pub body: HandshakeBody,
}

impl Handshake {
    pub fn deserialize(input: Buffer) -> IResult<Self> {
        let (input, msg_type) = HandshakeType::deserialize(input)?;
        let (input, length) = take(input, 3u8)?;
        let length = u24::from(length);

        let (input, fragment) = take(input, length)?;
        let fragment = Buffer::new(fragment, length);

        let body = match msg_type {
            HandshakeType::ServerHello => {
                let (_, body) = ServerHello::deserialize(fragment)?;
                HandshakeBody::ServerHello(body)
            }
            HandshakeType::Certificate => {
                let (_, body) = Certificate::deserialize(fragment)?;
                HandshakeBody::Certificate(body)
            }
            HandshakeType::ServerHelloDone => HandshakeBody::ServerHelloDone(()),
            _ => unimplemented!(),
        };

        Ok((
            input,
            Handshake {
                msg_type,
                length,
                body,
            },
        ))
    }
}

#[repr(C)]
#[derive(Serialize, Debug)]
pub enum HandshakeBody {
    ClientHello(ClientHello),
    ServerHello(ServerHello),
    Certificate(Certificate),
    ServerHelloDone(()),
    ClientKeyExchange(ClientKeyExchange),
}

impl_enum_try_from! {
    #[allow(dead_code)]
    #[repr(u8)]
    #[derive(Serialize_repr, Debug)]
    pub enum HandshakeType {
        HelloRequest = 0,
        ClientHello = 1,
        ServerHello = 2,
        Certificate = 11,
        ServerKeyExchange = 12,
        CertificateRequest = 13,
        ServerHelloDone = 14,
        CertificateVerify = 15,
        ClientKeyExchange = 16,
        Finished = 20,
    },
    u8,
    Error,
    Error::InvalidValue
}

impl HandshakeType {
    pub fn deserialize(input: Buffer) -> IResult<Self> {
        let (input, msg_type) = be_u8(input)?;
        let msg_type = HandshakeType::try_from(msg_type).unwrap();
        Ok((input, msg_type))
    }
}

#[derive(Serialize, Debug)]
pub struct Certificate {
    pub length: u24,
    pub certificate_list: Opaque<u24>,
}

impl Certificate {
    pub fn deserialize(input: Buffer) -> IResult<Self> {
        let (input, length) = u24::deserialize(input)?;
        let (input, certificate_list) = Opaque::<u24>::deserialize(input)?;
        Ok((
            input,
            Certificate {
                length,
                certificate_list,
            },
        ))
    }
}

#[derive(Serialize, Debug)]
pub struct PreMasterSecret {
    pub protocol_version: ProtocolVersion,
    pub random: Opaque<u16>,
}

impl PreMasterSecret {
    pub fn to_bytes<O: ByteOrder>(&self) -> Vec<u8> {
        ser::to_bytes::<_, O>(self).unwrap()
    }
}

pub type ClientKeyExchange = Opaque<u16>;
