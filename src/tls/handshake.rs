use super::hello_messaage::{ClientHello, ServerHello};

use nom::{bytes::complete::take, number::complete::be_u8, IResult};
use serde::Serialize;
use serde_repr::Serialize_repr;

#[derive(Serialize, Debug)]
pub struct Handshake {
    pub msg_type: HandshakeType,
    pub length: [u8; 3],
    pub body: HandshakeBody,
}

impl<'a> Handshake {
    pub fn deserialize(input: &'a [u8]) -> IResult<&'a [u8], Self> {
        let (input, msg_type) = HandshakeType::deserialize(input)?;
        let (input, length) = take(3u8)(input)?;
        let length = length.try_into().unwrap();
        let (input, body) = match msg_type {
            HandshakeType::ServerHello => {
                let (input, body) = ServerHello::deserialize(input)?;
                (input, HandshakeBody::ServerHello(body))
            }
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
    pub fn deserialize(input: &[u8]) -> IResult<&[u8], Self> {
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
