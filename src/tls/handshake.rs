use super::hello_messaage::{ClientHello, ServerHello};
use super::{be_u8, take, u24, Buffer, IResult, Opaque};

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
}

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
}

impl HandshakeType {
    pub fn deserialize(input: Buffer) -> IResult<Self> {
        let (input, msg_type) = be_u8(input)?;
        let msg_type = match msg_type {
            0 => HandshakeType::HelloRequest,
            1 => HandshakeType::ClientHello,
            2 => HandshakeType::ServerHello,
            11 => HandshakeType::Certificate,
            12 => HandshakeType::ServerKeyExchange,
            13 => HandshakeType::CertificateRequest,
            14 => HandshakeType::ServerHelloDone,
            15 => HandshakeType::CertificateVerify,
            16 => HandshakeType::ClientKeyExchange,
            20 => HandshakeType::Finished,
            _ => panic!("Invalid handshake type"),
        };

        Ok((input, msg_type))
    }
}

#[derive(Serialize, Debug)]
pub struct Certificate {
    pub certificate_list: Opaque<u24>,
}

impl Certificate {
    pub fn deserialize(input: Buffer) -> IResult<Self> {
        let (input, certificate_list) = Opaque::<u24>::deserialize(input)?;
        Ok((input, Certificate { certificate_list }))
    }
}
