mod tls;
use tls::*;

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
        chipher_suites: CipherSuites {
            length: 2,
            data: vec![ChiperSuite::TLS_RSA_WITH_AES_128_GCM_SHA256],
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
