mod tls;
use tls::*;

use anyhow::Result;
use rsa::{pkcs8::DecodePublicKey, Pkcs1v15Encrypt, RsaPublicKey};
use ser::NetworkEndian;
use std::{
    io::{Read, Write},
    net::TcpStream,
    time::{SystemTime, UNIX_EPOCH},
    vec,
};
use x509_parser::parse_x509_certificate;

#[allow(dead_code)]
fn epoch_time() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32
}

fn main() -> Result<()> {
    let client_random = Random {
        gmt_unix_time: 0,
        random_bytes: vec![0; 28].try_into().unwrap(), // テストなので0パディングしちゃう
    };
    let client_hello = ClientHello {
        protocol_version: ProtocolVersion::TLSv1_2,
        random: client_random,
        session_id: Opaque::<u8> {
            length: 0,
            data: vec![],
        },
        chipher_suites: CipherSuites {
            length: 2,
            data: vec![CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256],
        },
        compression_methods: CompressionMethods {
            length: 1,
            data: vec![CompressionMethod::Null],
        },
        extensions: Extensions {
            length: 8,
            data: vec![Extension {
                extension_type: ExtensionType::SignatureAlgorithms,
                data: Vector {
                    length: 4,
                    data: vec![ExtensionData::SignatureAlgorithms(Vector {
                        length: 2,
                        data: vec![SignatureAndHashAlgorithm {
                            hash: HashAlgorithm::SHA256,
                            signature: SignatureAlgorithm::RSA,
                        }],
                    })],
                },
            }],
        },
    };

    let client_hello_size = ser::bytes_size(&client_hello)?;

    let handshake = Handshake {
        msg_type: HandshakeType::ClientHello,
        length: u24::from(client_hello_size),
        body: HandshakeBody::ClientHello(client_hello),
    };

    let tls_plaintext = TLSRecord {
        content_type: ContentType::Handshake,
        protocol_version: ProtocolVersion::TLSv1_2,
        length: client_hello_size as u16 + 4,
        fragment: Fragment::Handshake(handshake),
    };
    println!("=> {:?}", tls_plaintext);

    let data = ser::to_bytes::<_, NetworkEndian>(&tls_plaintext)?;
    let mut client = TcpStream::connect("127.0.0.1:443")?;
    client.write_all(&data)?;

    let mut buf = vec![0u8; 4096];
    let read_bytes = client.read(&mut buf)?;
    let response = deserialize_tls_record(&buf, read_bytes);
    for record in &response {
        println!("<= {:?}", record);
    }
    buf.clear();

    // 0番目がServerHelloだろう
    let server_random = match &response[0].fragment {
        Fragment::Handshake(Handshake {
            body: HandshakeBody::ServerHello(server_hello),
            ..
        }) => server_hello.random,
        _ => panic!("Unexpected message"),
    };
    let server_random = server_random.random_bytes.as_slice();

    // 1番目がCertificateだろう
    let server_cert = match &response[1].fragment {
        Fragment::Handshake(Handshake {
            body: HandshakeBody::Certificate(cert),
            ..
        }) => cert,
        _ => panic!("Unexpected message"),
    };

    // 証明書のverifyは未実装
    println!("Certificate verify is currentry not implemented");

    // KeyExchange
    let (_, cert) = parse_x509_certificate(&server_cert.certificate_list.data)?;
    let public_key = RsaPublicKey::from_public_key_der(cert.public_key().raw)?;

    let pre_master_secret = PreMasterSecret {
        protocol_version: ProtocolVersion::TLSv1_2,
        random: Opaque::<u16> {
            length: 46,
            data: client_random.random_bytes.to_vec(),
        },
    };
    let enc = public_key.encrypt(
        &mut rand::thread_rng(),
        Pkcs1v15Encrypt,
        &pre_master_secret.to_bytes::<NetworkEndian>(),
    )?;

    let client_key_exchange = ClientKeyExchange {
        length: enc.len() as u16,
        data: enc,
    };
    let handshake = Handshake {
        msg_type: HandshakeType::ClientKeyExchange,
        length: u24::from(client_key_exchange.length + 2),
        body: HandshakeBody::ClientKeyExchange(client_key_exchange),
    };
    let tls_plaintext = TLSRecord {
        content_type: ContentType::Handshake,
        protocol_version: ProtocolVersion::TLSv1_2,
        length: (handshake.length.to_u16() + 4),
        fragment: Fragment::Handshake(handshake),
    };
    client.write_all(&ser::to_bytes::<_, NetworkEndian>(&tls_plaintext)?)?;

    let tls_plaintext = TLSRecord {
        content_type: ContentType::ChangeCipherSpec,
        protocol_version: ProtocolVersion::TLSv1_2,
        length: 1,
        fragment: Fragment::ChangeCipherSpec(ChangeCipherSpec::ChangeCipherSpec),
    };
    client.write_all(&ser::to_bytes::<_, NetworkEndian>(&tls_plaintext)?)?;

    let read_bytes = client.read(&mut buf)?;
    let response = deserialize_tls_record(&buf, read_bytes);
    for record in &response {
        println!("<= {:?}", record);
    }

    Ok(())
}
