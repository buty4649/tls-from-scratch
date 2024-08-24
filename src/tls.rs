mod handshake;
mod hello_messaage;

pub use handshake::*;
pub use hello_messaage::*;

use serde::Serialize;
use serde_repr::Serialize_repr;

#[allow(dead_code)]
#[repr(u16)]
#[derive(Serialize_repr, Debug)]
pub enum ProtocolVersion {
    SSLv3 = 0x0300,
    TLSv1 = 0x0301,
    TLSv1_1 = 0x0302,
    TLSv1_2 = 0x0303,
    TLSv1_3 = 0x0304,
}

#[derive(Serialize, Debug)]
pub struct Vector<T, D> {
    pub length: T,
    pub data: Vec<D>,
}

pub type Opaque<S> = Vector<S, u8>;

#[allow(non_camel_case_types)]
#[repr(u16)]
#[derive(Serialize_repr, Debug)]
pub enum ChiperSuite {
    TLS_RSA_WITH_AES_128_GCM_SHA256 = 0x009c,
}
