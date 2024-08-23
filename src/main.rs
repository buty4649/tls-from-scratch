use anyhow::Result;
use ser::NetworkEndian;
use serde::Serialize;
use serde_repr::Serialize_repr;
use std::{
    io::{BufReader, Read, Write},
    net::TcpStream,
    time::{SystemTime, UNIX_EPOCH},
    vec,
};

#[repr(C)]
#[derive(Serialize, Debug)]
struct TLSPlaintext {
    content_type: ContentType,
    protocol_version: ProtocolVersion,
    length: u16,
    fragment: Handshake,
}

#[allow(dead_code)]
#[repr(u8)]
#[derive(Serialize_repr, Debug)]
enum ContentType {
    ChangeCipherSpec = 20,
    Alert = 21,
    Handshake = 22,
    ApplicationData = 23,
}

#[allow(dead_code)]
#[repr(u16)]
#[derive(Serialize_repr, Debug)]
enum ProtocolVersion {
    SSLv3 = 0x0300,
    TLSv1 = 0x0301,
    TLSv1_1 = 0x0302,
    TLSv1_2 = 0x0303,
    TLSv1_3 = 0x0304,
}

#[repr(C)]
#[derive(Serialize, Debug)]
enum HandshakeBody {
    ClientHello(ClientHello),
}

#[derive(Serialize, Debug)]
struct Handshake {
    msg_type: HandshakeType,
    length: [u8; 3],
    body: HandshakeBody,
}

#[allow(dead_code)]
#[repr(u8)]
#[derive(Serialize_repr, Debug)]
enum HandshakeType {
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

#[derive(Serialize, Debug)]
struct ClientHello {
    protocol_version: ProtocolVersion,
    random: Random,
    session_id: Opaque<u8>,
    chipher_suites: CipherSuite,
    compression_methods: CompressionMethod,
    extension_length: u16,
    extensions: Extension,
}

#[derive(Serialize, Debug)]
struct Random {
    gmt_unix_time: u32,
    random_bytes: [u8; 28],
}

#[derive(Serialize, Debug)]
struct Opaque<T> {
    length: T,
    data: Vec<u8>,
}

#[derive(Serialize, Debug)]
struct CipherSuite {
    length: u16,
    cipher_suite: Vec<u16>,
}

#[derive(Serialize, Debug)]
struct CompressionMethod {
    length: u8,
    compression_methods: Vec<u8>,
}

#[derive(Serialize, Debug)]
struct Extension {
    extension_type: ExtensionType,
    length: u16,
    supported_signature_algorithms_length: u16,
    extension_data: ExtensionData,
}

#[allow(non_camel_case_types)]
#[repr(u16)]
#[derive(Serialize_repr, Debug)]
enum ExtensionType {
    signature_algorithms = 13,
}

#[derive(Serialize, Debug)]
enum ExtensionData {
    SignatureAlgorithms(Vec<SignatureAndHashAlgorithm>),
}

#[derive(Serialize, Debug)]
struct SignatureAndHashAlgorithm {
    hash: HashAlgorithm,
    signature: SignatureAlgorithm,
}

#[allow(dead_code, clippy::upper_case_acronyms)]
#[repr(u8)]
#[derive(Serialize_repr, Debug)]
enum HashAlgorithm {
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
enum SignatureAlgorithm {
    Anonymous = 0,
    RSA = 1,
    DSA = 2,
    ECDSA = 3,
}

#[allow(dead_code)]
fn epoch_time() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32
}

fn main() -> Result<()> {
    let client_hello = ClientHello {
        protocol_version: ProtocolVersion::TLSv1_2,
        random: Random {
            gmt_unix_time: 0,
            random_bytes: vec![0; 28].try_into().unwrap(), // テストなので0パディングしちゃう
        },
        session_id: Opaque::<u8> {
            length: 0,
            data: vec![],
        },
        chipher_suites: CipherSuite {
            length: 2,
            cipher_suite: vec![0x09c], // TLS_RSA_WITH_AES_128_GCM_SHA256
        },
        compression_methods: CompressionMethod {
            length: 1,
            compression_methods: vec![0],
        },
        extension_length: 8,
        extensions: Extension {
            extension_type: ExtensionType::signature_algorithms,
            length: 4,
            supported_signature_algorithms_length: 2,
            extension_data: ExtensionData::SignatureAlgorithms(vec![SignatureAndHashAlgorithm {
                hash: HashAlgorithm::SHA256,
                signature: SignatureAlgorithm::RSA,
            }]),
        },
    };

    let client_hello_size = ser::bytes_size(&client_hello)?;
    println!("client_hello_size: {}", client_hello_size);

    let handshake = Handshake {
        msg_type: HandshakeType::ClientHello,
        length: [
            (client_hello_size >> 16 & 0xff) as u8,
            (client_hello_size >> 8 & 0xff) as u8,
            (client_hello_size & 0xff) as u8,
        ],
        body: HandshakeBody::ClientHello(client_hello),
    };

    let tls_plaintext = TLSPlaintext {
        content_type: ContentType::Handshake,
        protocol_version: ProtocolVersion::TLSv1_2,
        length: client_hello_size as u16 + 4,
        fragment: handshake,
    };

    println!("{:?}", tls_plaintext);

    let data = ser::to_bytes::<_, NetworkEndian>(&tls_plaintext)?;
    println!("binary:");
    for (i, b) in data.iter().enumerate() {
        print!("{:02x}", b);
        if i % 8 == 7 {
            print!("     "); // 8個目と9個目の間にスペースを5つ入れる
        } else {
            print!(" "); // それ以外はスペースを1つだけ入れる
        }
        if (i + 1) % 16 == 0 {
            println!(); // 16個ごとに改行
        }
    }
    println!(); // 最後の行に改行を追加

    let mut client = TcpStream::connect("127.0.0.1:443")?;
    client.write_all(&data)?;

    let mut reader = BufReader::new(client);
    let mut buf = vec![0; 128];
    let size = reader.read(&mut buf)?;

    println!("response: {:?}", &buf[..size]);

    Ok(())
}
