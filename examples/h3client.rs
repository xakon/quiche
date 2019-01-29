// Copyright (C) 2019, Cloudflare, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright
//       notice, this list of conditions and the following disclaimer.
//
//     * Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in the
//       documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#[macro_use]
extern crate log;

use ring::rand::*;

const LOCAL_CONN_ID_LEN: usize = 16;

const MAX_DATAGRAM_SIZE: usize = 1452;

const USAGE: &str = "Usage:
  h3client [options] URL
  h3client -h | --help

Options:
  --wire-version VERSION  The version number to send to the server [default: babababa].
  --no-verify             Don't verify server's certificate.
  -h --help               Show this screen.
";

fn main() {
    let mut buf = [0; 65535];
    let mut out = [0; MAX_DATAGRAM_SIZE];

    env_logger::init();

    let args = docopt::Docopt::new(USAGE)
                      .and_then(|dopt| dopt.parse())
                      .unwrap_or_else(|e| e.exit());

    let url = url::Url::parse(args.get_str("URL")).unwrap();

    let socket = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
    socket.connect(&url).unwrap();

    let poll = mio::Poll::new().unwrap();
    let mut events = mio::Events::with_capacity(1024);

    let socket = mio::net::UdpSocket::from_socket(socket).unwrap();
    poll.register(&socket, mio::Token(0),
                  mio::Ready::readable(),
                  mio::PollOpt::edge()).unwrap();

    let mut scid: [u8; LOCAL_CONN_ID_LEN] = [0; LOCAL_CONN_ID_LEN];
    SystemRandom::new().fill(&mut scid[..]).unwrap();

    let version = args.get_str("--wire-version");
    let version = u32::from_str_radix(version, 16).unwrap();

    let mut config = quiche::h3::H3Config::new(version).unwrap();

    config.quiche_config.verify_peer(true);

    config.quiche_config.set_application_protos(&[b"h3-17", b"hq-17", b"http/0.9"]).unwrap();

    config.quiche_config.set_idle_timeout(30);
    config.quiche_config.set_max_packet_size(MAX_DATAGRAM_SIZE as u64);
    config.quiche_config.set_initial_max_data(10_000_000);
    config.quiche_config.set_initial_max_stream_data_bidi_local(1_000_000);
    config.quiche_config.set_initial_max_stream_data_bidi_remote(1_000_000);
    config.quiche_config.set_initial_max_streams_bidi(100);
    config.quiche_config.set_initial_max_streams_uni(100);
    config.quiche_config.set_disable_migration(true);

    if args.get_bool("--no-verify") {
        config.quiche_config.verify_peer(false);
    }

    if std::env::var_os("SSLKEYLOGFILE").is_some() {
        config.quiche_config.log_keys();
    }

    let mut h3conn = quiche::h3::connect(url.domain(), &scid, &mut config).unwrap();

    let write = match h3conn.quic_conn.send(&mut out) {
        Ok(v) => v,

        Err(e) => panic!("{} initial send failed: {:?}", h3conn.quic_conn.trace_id(), e),
    };

    socket.send(&out[..write]).unwrap();

    debug!("{} written {}", h3conn.quic_conn.trace_id(), write);

    let mut req_sent = false;

    loop {
        poll.poll(&mut events, h3conn.quic_conn.timeout()).unwrap();

        'read: loop {
            if events.is_empty() {
                debug!("timed out");

                h3conn.quic_conn.on_timeout();

                break 'read;
            }

            let len = match socket.recv(&mut buf) {
                Ok(v) => v,

                Err(e) => {
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        debug!("recv() would block");
                        break 'read;
                    }

                    panic!("recv() failed: {:?}", e);
                },
            };

            debug!("{} got {} bytes", h3conn.quic_conn.trace_id(), len);

            // Process potentially coalesced packets.
            let read = match h3conn.quic_conn.recv(&mut buf[..len]) {
                Ok(v)  => v,

                Err(quiche::Error::Done) => {
                    debug!("{} done reading", h3conn.quic_conn.trace_id());
                    break;
                },

                Err(e) => {
                    error!("{} recv failed: {:?}", h3conn.quic_conn.trace_id(), e);
                    h3conn.quic_conn.close(false, e.to_wire(), b"fail").unwrap();
                    break 'read;
                },
            };

            debug!("{} processed {} bytes", h3conn.quic_conn.trace_id(), read);
        }

        if h3conn.quic_conn.is_closed() {
            debug!("{} connection closed", h3conn.quic_conn.trace_id());
            break;
        }

        if h3conn.quic_conn.is_established() && !req_sent {
            // TODO make opening control streams saner
            if !h3conn.is_established() {
                h3conn.send_settings();
                h3conn.open_qpack_streams();
            }

            info!("{} sending HTTP request for {}", h3conn.quic_conn.trace_id(), url.path());

            let req = if args.get_bool("--http1") {
                format!("GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: quiche\r\n\r\n",
                    url.path(), url.host().unwrap())
            } else {
                format!("GET {}\r\n", url.path())
            };

            //h3conn.send_request(req);
            req_sent = true;
        }

        let streams: Vec<u64> = h3conn.quic_conn.readable().collect();
        for s in streams {
            info!("{} stream {} is readable", h3conn.quic_conn.trace_id(), s);
            if h3conn.handle_stream(s).is_err() {
                break;
            }

        }

        loop {
            let write = match h3conn.quic_conn.send(&mut out) {
                Ok(v) => v,

                Err(quiche::Error::Done) => {
                    debug!("{} done writing", h3conn.quic_conn.trace_id());
                    break;
                },

                Err(e) => {
                    error!("{} send failed: {:?}", h3conn.quic_conn.trace_id(), e);
                    h3conn.quic_conn.close(false, e.to_wire(), b"fail").unwrap();
                    break;
                },
            };

            // TODO: coalesce packets.
            socket.send(&out[..write]).unwrap();

            debug!("{} written {}", h3conn.quic_conn.trace_id(), write);
        }

        if h3conn.quic_conn.is_closed() {
            info!("{} connection closed, {:?}", h3conn.quic_conn.trace_id(), h3conn.quic_conn.stats());
            break;
        }
    }
}
