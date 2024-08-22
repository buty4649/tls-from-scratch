use anyhow::Result;
use byteorder::{BigEndian, WriteBytesExt};
use std::{
    io::{BufReader, Read, Write},
    net::TcpStream,
    time::{SystemTime, UNIX_EPOCH},
    vec,
};

#[repr(C)]
#[derive(Debug)]
struct TLSPlaintext {
    content_type: ContentType,
    protocol_version: ProtocolVersion,
    length: u16,
    fragment: Handshake,
}

#[allow(dead_code)]
#[repr(u8)]
#[derive(Debug)]
enum ContentType {
    ChangeCipherSpec = 20,
    Alert = 21,
    Handshake = 22,
    ApplicationData = 23,
}

#[allow(dead_code)]
#[repr(u16)]
#[derive(Debug)]
enum ProtocolVersion {
    SSLv3 = 0x0300,
    TLSv1 = 0x0301,
    TLSv1_1 = 0x0302,
    TLSv1_2 = 0x0303,
    TLSv1_3 = 0x0304,
}

#[repr(C)]
#[derive(Debug)]
enum HandshakeBody {
    ClientHello(ClientHello),
}

#[derive(Debug)]
struct Handshake {
    msg_type: HandshakeType,
    length: [u8; 3],
    body: HandshakeBody,
}

#[allow(dead_code)]
#[repr(u8)]
#[derive(Debug)]
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

#[derive(Debug)]
struct ClientHello {
    protocol_version: ProtocolVersion,
    random: Random,
    session_id: Opaque<u8>,
    chipher_suites: CipherSuite,
    compression_methods: CompressionMethod,
    extension_length: u16,
    extensions: Extension,
}

#[derive(Debug)]
struct Random {
    gmt_unix_time: u32,
    random_bytes: [u8; 28],
}

#[derive(Debug)]
struct Opaque<T> {
    length: T,
    data: Vec<u8>,
}

#[derive(Debug)]
struct CipherSuite {
    length: u16,
    cipher_suite: Vec<u16>,
}

#[derive(Debug)]
struct CompressionMethod {
    length: u8,
    compression_methods: Vec<u8>,
}

#[derive(Debug)]
struct Extension {
    extension_type: ExtensionType,
    length: u16,
    supported_signature_algorithms_length: u16,
    extension_data: ExtensionData,
}

#[allow(non_camel_case_types)]
#[repr(u16)]
#[derive(Debug)]
enum ExtensionType {
    signature_algorithms = 13,
}

#[derive(Debug)]
enum ExtensionData {
    SignatureAlgorithms(Vec<SignatureAndHashAlgorithm>),
}

#[derive(Debug)]
struct SignatureAndHashAlgorithm {
    hash: HashAlgorithm,
    signature: SignatureAlgorithm,
}

#[allow(dead_code, clippy::upper_case_acronyms)]
#[repr(u8)]
#[derive(Debug)]
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
#[derive(Debug)]
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
    let mut data = Vec::<u8>::new();

    let client_hello = ClientHello {
        protocol_version: ProtocolVersion::TLSv1_2,
        random: Random {
            gmt_unix_time: epoch_time(),
            random_bytes: vec![1; 28].try_into().unwrap(), // テストなので0パディングしちゃう
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

    let client_hello_size = 2
        // random
        + 32
        // session_id
        + 1
        + client_hello.session_id.length as u32
        // chipher_suites
        + 2
        + client_hello.chipher_suites.length as u32
        // compression_methods
        + 1
        + client_hello.compression_methods.length as u32
        // extensions
        + 2
        + client_hello.extension_length as u32;

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

    data.write_u8(tls_plaintext.content_type as u8)?;
    data.write_u16::<BigEndian>(tls_plaintext.protocol_version as u16)?;
    data.write_u16::<BigEndian>(tls_plaintext.length)?;
    data.write_u8(tls_plaintext.fragment.msg_type as u8)?;
    for l in tls_plaintext.fragment.length.iter() {
        data.write_u8(*l)?;
    }
    match tls_plaintext.fragment.body {
        HandshakeBody::ClientHello(client_hello) => {
            data.write_u16::<BigEndian>(client_hello.protocol_version as u16)?;
            data.write_u32::<BigEndian>(client_hello.random.gmt_unix_time)?;
            for b in &client_hello.random.random_bytes {
                data.write_u8(*b)?;
            }
            data.write_u8(client_hello.session_id.length)?;
            data.write_all(&client_hello.session_id.data)?;
            data.write_u16::<BigEndian>(client_hello.chipher_suites.length)?;
            for b in &client_hello.chipher_suites.cipher_suite {
                data.write_u16::<BigEndian>(*b)?;
            }
            data.write_u8(client_hello.compression_methods.length)?;
            data.write_all(&client_hello.compression_methods.compression_methods)?;

            data.write_u16::<BigEndian>(client_hello.extension_length)?;
            data.write_u16::<BigEndian>(client_hello.extensions.extension_type as u16)?;
            data.write_u16::<BigEndian>(client_hello.extensions.length)?;
            match client_hello.extensions.extension_data {
                ExtensionData::SignatureAlgorithms(signature_algorithms) => {
                    data.write_u16::<BigEndian>(client_hello.extensions.supported_signature_algorithms_length)?;
                    for sa in signature_algorithms {
                        data.write_u8(sa.hash as u8)?;
                        data.write_u8(sa.signature as u8)?;
                    }
                }
            }
        }
    }

    print!("binary: ");
    for b in &data {
        print!("{:02x} ", b);
    }
    println!();

    let mut client = TcpStream::connect("127.0.0.1:443")?;
    client.write_all(&data)?;

    let mut reader = BufReader::new(client);
    let mut buf = vec![0; 128];
    let size = reader.read(&mut buf)?;

    println!("response: {:?}", &buf[..size]);

    Ok(())
}
