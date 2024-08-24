use super::hello_messaage::ClientHello;

use serde::Serialize;
use serde_repr::Serialize_repr;

#[repr(C)]
#[derive(Serialize, Debug)]
pub enum HandshakeBody {
    ClientHello(ClientHello),
}

#[derive(Serialize, Debug)]
pub struct Handshake {
    pub msg_type: HandshakeType,
    pub length: [u8; 3],
    pub body: HandshakeBody,
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
