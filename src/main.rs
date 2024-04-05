use bytes::{Buf, Bytes};
use clap::Parser;
use mysql_async::{Opts, Pool};
use mysql_async::prelude::Queryable;
use tokio::net::{TcpStream, TcpListener};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::io;

#[derive(Parser, Clone)]
struct CommandLineArguments {
    #[clap(env = "LISTEN_HOST")]
    host: String,
    #[clap(env = "LISTEN_PORT")]
    port: u16,
    #[clap(env = "DEFAULT_SERVER")]
    default_server: String,
    #[clap(env = "DATABASE_URL")]
    database_url: String,
}

#[allow(dead_code)]
struct ProtocolBackendServer {
    host: String,
    protocol: String,
}

#[tokio::main]
async fn main() {
    let args = CommandLineArguments::parse();
    tracing_subscriber::fmt::init();

    let opts = Opts::from_url(&args.database_url).unwrap();
    let pool = Pool::new(opts);

    let proxy_server = TcpListener::bind((args.host.clone(), args.port)).await.unwrap();
    println!("Magma Modular Proxy Loaded. Listening on {}:{}", args.host, args.port);

    while let Ok((client, _)) = proxy_server.accept().await {
        let local_pool = pool.clone();
        let local_default_server = args.default_server.clone();
        tokio::spawn(async move {
            let _ = handle_client_conn(client, local_pool, local_default_server).await;
        });
    };
}

async fn handle_client_conn(mut client: TcpStream, pool: Pool, default_server: String) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client_recv, mut client_send) = client.split();

    let mut buf_raw = vec![0u8; 1024];
    let read_count = client_recv.read(&mut buf_raw).await?;
    let mut buf = Bytes::from(buf_raw.clone());

    // Second stage buffer if required
    let mut second_stage_buffer = vec![0u8; 5];

    // Flags
    let mut block_connection_hash_response = false;
    let mut is_ucs2 = true;

    // 1.7.2+ (13w41a) Netty Rewrite Packet
    let protocol_version = if read_count > 1 && buf[1] == 0x00 && buf[0] != 0x00 && buf[0] != 0x02 {
        // Read the packet length
        let _ = read_var_int(&mut buf);

        // Skip one 0x00
        buf.advance(1);

        // Get the protocol version
        let protocol = read_var_int(&mut buf);

        format!("N{}", protocol)
    // Pre-Netty, Post 1.3 (12w30d) Server List Ping w/Magic Number 0x01
    } else if buf[0] == 0xFE && buf[1] == 0x01 {
        "PreNettyPost39ListPing".to_string()
    // Pre-Netty, Post 1.3 (12w21a) New Handshake
    } else if buf[0] == 0x02 && buf[1] <= 80 && buf[1] >= 33 {
        format!("P{}", buf[1])
    // Pre-Netty, Pre 1.3 (12w30d) Old Server List Ping
    } else if buf[0] == 0xFE && read_count == 1 {
        "PreNettyPre39ListPing".to_string()
    // Pre-Netty, Pre 1.3 (12w21a) Old Handshake
    } else if buf[0] == 0x02 {
        // Skip packet ID & Decode String to advance bytes appropriately
        buf.advance(1);
        let str_length = buf.get_i16();
        let str_bytes_length = read_count - 3;
        is_ucs2 = (str_bytes_length / 2) == str_length as usize;

        // Need to fake the connection hash.
        block_connection_hash_response = true;
        if is_ucs2 {
            client_send.write_u8(0x02).await?;
            client_send.write_all(&string16_encode("-")).await?;
        } else {
            client_send.write_u8(0x02).await?;
            client_send.write_all(&string8_encode("-")).await?;
        }

        // Receive the buffer to the actual length
        buf_raw.resize(read_count, 0);

        // Await for the actual login request...
        client_recv.read_exact(&mut second_stage_buffer).await?;
        let mut buf_temp_bytes = Bytes::from(second_stage_buffer.clone());

        // Get the actual i32
        buf_temp_bytes.advance(1);
        format!("P{}", buf_temp_bytes.get_i32())
    }
    else {
        println!("Unknown Format Received. First three bytes: {:#x?}, {:#x?}, {:#x?}", buf[0], buf[1], buf[2]);
        "Unknown".to_string()
    };

    // Turn the protocol version into a server address according to the config.
    let mut conn = pool.get_conn().await?;
    let backend_servers: Option<(i32, String, String)> = conn.exec_first("SELECT * FROM protocol_rules WHERE protocol = ?", (protocol_version.clone(),)).await?;
    let backend_server = if let Some(backend) = backend_servers {
        backend.1
    } else {
        default_server
    };

    drop(conn);

    // The stuff required to proxy the TCP through...
    let mut server = TcpStream::connect(backend_server).await?;
    let (mut server_recv, mut server_send) = server.split();

    // Send out the read in bit to avoid disrupting communications
    server_send.write_all(&buf_raw[..read_count]).await?;

    // If needed, block out the server's handshake response.
    if block_connection_hash_response {
        let mut buf_temp = vec![0u8; 3];
        server_recv.read_exact(&mut buf_temp).await?;

        let mut buf_temp_bytes = Bytes::from(buf_temp);
        let _packet_id = buf_temp_bytes.get_i8();
        let str_length = buf_temp_bytes.get_i16();
        let buf_temp_size = if is_ucs2 {
            str_length * 2
        } else {
            str_length
        };

        let mut buf_temp_recv_two = vec![0u8; buf_temp_size as usize];
        server_recv.read_exact(&mut buf_temp_recv_two).await?;

        // Send through the login request to the server
        server_send.write_all(&second_stage_buffer).await?;
    }

    // Print to the console what we are doing
    println!("Connecting {} with version {} to {}", client_recv.peer_addr()?, protocol_version, server_recv.peer_addr()?);
    
    // Spawn two tasks to handle bidirectional data transfer between client and target
    let client_to_server = io::copy(&mut client_recv, &mut server_send);
    let server_to_client = io::copy(&mut server_recv, &mut client_send);

    // Await the tasks
    tokio::try_join!(client_to_server, server_to_client)?;

    drop(client);
    drop(server);

    Ok(())
}

// ------ HELPER FUNCTIONS -------
const SEGMENT_BITS: u8 = 0b0111_1111;
const CONTINUE_BIT: u8 = 0b1000_0000;
fn read_var_int(buf: &mut Bytes) -> u32 {
    let mut value: u32 = 0;
    let mut position: usize = 0;

    loop {
        let current_byte = buf.get_u8();
        value |= ((current_byte & SEGMENT_BITS) as u32) << position;

        if (current_byte & CONTINUE_BIT) == 0 {
            break;
        }

        position += 7;

        if position >= 32 {
            panic!("VarInt is too big");
        }
    }

    value
}

pub fn string16_decode(raw_8: &mut Bytes) -> (String, i16) {
    let length = raw_8.get_i16();
    let length_usize = usize::try_from(length).expect("String length should never be negative.");

    let mut raw_u16 = vec![0; length_usize];

    for count in 0..length_usize {
        raw_u16[count] = raw_8.get_u16();
    }

     (String::from_utf16(&raw_u16).unwrap(), length)
}

pub fn string16_encode(str: &str) -> Vec<u8> {
    let mut str16_vec = Vec::new();

    let length = i16::try_from(str.chars().count()).expect("Length of string16 may not exceeded 32,767 characters");
    let mut length_vec = Vec::from(length.to_be_bytes());
    str16_vec.append(&mut length_vec);

    let vec_utf16: Vec<u16> = str.encode_utf16().collect();
    let vec_u8: Vec<[u8; 2]> = vec_utf16.iter().map(|x| x.to_be_bytes()).collect();
    let mut str_u8: Vec<u8> = vec_u8.iter().flatten().cloned().collect();
    str16_vec.append(&mut str_u8);

    str16_vec
}

pub fn string8_decode(raw_8: &mut Bytes) -> (String, i16) {
    let length = raw_8.get_i16();

    let string_bytes = raw_8.copy_to_bytes(length as usize);
    let string = mutf8::decode(&string_bytes).unwrap().to_string();

    (string, length)
}

pub fn string8_encode(str: &str) -> Vec<u8> {
    let mut str16_vec = Vec::with_capacity(str.chars().count() + 2);

    let length = i16::try_from(str.chars().count()).expect("Length of string8 may not exceeded 32,767 characters");
    let mut length_vec = Vec::from(length.to_be_bytes());
    str16_vec.append(&mut length_vec);

    let mut str_u8: Vec<u8> = mutf8::encode(str).to_vec();

    str16_vec.append(&mut str_u8);

    str16_vec
}
