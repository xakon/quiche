
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

//mod qpack;
pub mod frame;

use crate::octets;
use super::Result;
use super::stream;

const H3_CONTROL_STREAM_TYPE_ID:    u8 = 0x43;
const H3_PUSH_STREAM_TYPE_ID:       u8 = 0x50;
const QPACK_ENCODER_STREAM_TYPE_ID: u8 = 0x48;
const QPACK_DECODER_STREAM_TYPE_ID: u8 = 0x68;

pub struct H3Config {
    pub quiche_config: super::Config,
    pub root_dir: String,
    pub num_placeholders: u16,
    pub max_header_list_size: u16,
    pub qpack_max_table_capacity: u16,
    pub qpack_blocked_streams: u16,
}

impl H3Config {

    /// Creates a config object with the given version.
    #[allow(clippy::new_ret_no_self)]
    pub fn new(version: u32) -> Result<H3Config> {

        Ok(H3Config {
            quiche_config: super::Config::new(version).unwrap(),
            root_dir: String::new(),
            num_placeholders: 16,
            max_header_list_size: 0,
            qpack_max_table_capacity: 0,
            qpack_blocked_streams: 0
        })
    }

    pub fn set_root_dir(&mut self, root_dir: &String) {
        self.root_dir = String::clone(root_dir);
    }

    pub fn set_num_placeholders(&mut self, num_placeholders: u16) {
        self.num_placeholders = num_placeholders;
    }

    pub fn set_max_header_list_size(&mut self, max_header_list_size: u16) {
        self.max_header_list_size = max_header_list_size;
    }

    pub fn set_qpack_max_table_capacity(&mut self, qpack_max_table_capacity: u16) {
        self.qpack_max_table_capacity = qpack_max_table_capacity;
    }

    pub fn set_qpacked_blocked_streams(&mut self, qpack_blocked_streams: u16) {
        self.qpack_blocked_streams = qpack_blocked_streams;
    }

}

/// An HTTP/3 connection.
pub struct H3Connection {
    pub quic_conn: Box<super::Connection>,

    root_dir: String,
    num_placeholders: u16,
    max_header_list_size: u16,
    qpack_max_table_capacity: u16,
    qpack_blocked_streams: u16,

    control_stream_open: bool,
    qpack_control_streams_open: bool,
}

impl H3Connection {
    #[allow(clippy::new_ret_no_self)]
    fn new(scid: &[u8], odcid: Option<&[u8]>, config: &mut H3Config,
           is_server: bool) -> Result<Box<H3Connection>> {

            let root = String::clone(&config.root_dir); // TODO shouldn't need to clone here

            Ok(Box::new(H3Connection {
                quic_conn: super::Connection::new(scid, odcid, &mut config.quiche_config, is_server)?,
                root_dir: root,
                num_placeholders: config.num_placeholders,
                max_header_list_size: config.max_header_list_size,
                qpack_max_table_capacity: config.qpack_max_table_capacity,
                qpack_blocked_streams: config.qpack_blocked_streams,
                control_stream_open: false,
                qpack_control_streams_open: false,
            }))
    }

    fn get_control_stream_id(&mut self) -> u64 {
        // TODO get an available unidirectional stream ID more nicely
        if self.quic_conn.is_server {
            return 0x3;
        } else {
            return 0x2;
        }
    }

    fn get_encoder_stream_id(&mut self) -> u64 {
        // TODO get an available unidirectional stream ID more nicely
        if self.quic_conn.is_server {
            return 0x7;
        } else {
            return 0x6;
        }
    }

    fn get_decoder_stream_id(&mut self) -> u64 {
        // TODO get an available unidirectional stream ID more nicely
        if self.quic_conn.is_server {
            return 0x11;
        } else {
            return 0x10;
        }
    }

    pub fn open_control_stream(&mut self) {
        if !self.control_stream_open {
            let mut d: [u8; 128] = [42; 128];
            let mut b = octets::Octets::with_slice(&mut d);
            b.put_u8(H3_CONTROL_STREAM_TYPE_ID);
            let off = b.off();
            let stream_id = self.get_control_stream_id();
            self.quic_conn.stream_send(stream_id, &mut d[..off], false).unwrap();

            self.control_stream_open = true;
        }
    }

    pub fn open_qpack_streams(&mut self) {
        if !self.qpack_control_streams_open {
            let mut e: [u8; 128] = [42; 128];
            let mut enc_b = octets::Octets::with_slice(&mut e);
            enc_b.put_u8(QPACK_ENCODER_STREAM_TYPE_ID);
            let off = enc_b.off();
            let stream_id = self.get_encoder_stream_id();
            self.quic_conn.stream_send(stream_id, &mut e[..off], false).unwrap();

            let mut d: [u8; 128] = [42; 128];
            let mut dec_b = octets::Octets::with_slice(&mut d);
            dec_b.put_u8(QPACK_DECODER_STREAM_TYPE_ID);
            let off = dec_b.off();
            let stream_id = self.get_decoder_stream_id();
            self.quic_conn.stream_send(stream_id, &mut d[..off], false).unwrap();

            self.qpack_control_streams_open = true;
        }
    }

    // Send SETTINGS frame based on H3 config
    pub fn send_settings(&mut self) {
        self.open_control_stream();

        let mut d: [u8; 128] = [42; 128];

        let frame = frame::H3Frame::Settings {
            num_placeholders: Some(16),
            max_header_list_size: Some(1024),
            qpack_max_table_capacity: None,
            qpack_blocked_streams: None
        };

        let mut b = octets::Octets::with_slice(&mut d);

        frame.to_bytes(&mut b).unwrap();
        let off = b.off();
        let stream_id = self.get_control_stream_id();

        self.quic_conn.stream_send(stream_id, &mut d[..off], false).unwrap();
    }

    // Send a no-body request
    pub fn send_request(&mut self, request: std::string::String ) {
        let mut d: [u8; 128] = [42; 128];

        let req_frame = frame::H3Frame::Headers {
            header_block: request.as_bytes().to_vec()
        };

        let mut b = octets::Octets::with_slice(&mut d);
        req_frame.to_bytes(&mut b).unwrap();
        let off = b.off();

        // TODO get an available stream number
        self.quic_conn.stream_send(0, &mut d[..off], true).unwrap();
    }

    // Send a response
    pub fn send_response(&mut self, stream: u64, status_line: std::string::String, body: std::string::String ) {
        let mut d: [u8; 128] = [42; 128];

        let headers = frame::H3Frame::Headers {
            header_block: status_line.as_bytes().to_vec()
        };

        let mut b = octets::Octets::with_slice(&mut d);
        headers.to_bytes(&mut b).unwrap();

        if !body.is_empty() {
            let data = frame::H3Frame::Data {
                payload: body.as_bytes().to_vec()
            };
            data.to_bytes(&mut b).unwrap();
        }

        let off = b.off();

        info!("{} sending response of size {} on stream {}",
                            self.quic_conn.trace_id(), off, stream);

        if let Err(e) = self.quic_conn.stream_send(stream, &mut d[..off], true) {
            error!("{} stream send failed {:?}", self.quic_conn.trace_id(), e);
        }
    }

    pub fn handle_stream(&mut self, stream: u64) {
        let mut stream_data = match self.quic_conn.stream_recv(stream, std::usize::MAX) {
            Ok(v) => v,

            Err(super::Error::Done) => return,

            Err(e) => panic!("{} stream recv failed {:?}",
                            self.quic_conn.trace_id(), e),
        };

        info!("{} stream {} has {} bytes (fin? {})", self.quic_conn.trace_id(),
            stream, stream_data.len(), stream_data.fin());

        // H3 unidirectional streams have types as first byte
        if !stream::is_bidi(stream) {

            if stream_data.off() == 0 {
                //dbg!(&stream_data);
                let mut o = octets::Octets::with_slice(&mut stream_data);
                let stream_type = o.get_u8().unwrap();
                match stream_type {
                    H3_CONTROL_STREAM_TYPE_ID => {
                        info!("{} stream {} is a control stream", self.quic_conn.trace_id(), stream);
                    },
                    H3_PUSH_STREAM_TYPE_ID => {
                        info!("{} stream {} is a push stream", self.quic_conn.trace_id(), stream);
                    },
                    QPACK_ENCODER_STREAM_TYPE_ID => {
                        info!("{} stream {} is a QPACK encoder stream", self.quic_conn.trace_id(), stream);
                    },
                    QPACK_DECODER_STREAM_TYPE_ID => {
                        info!("{} stream {} is a QPACK decoder stream", self.quic_conn.trace_id(), stream);
                    },
                    _ => {
                        info!("{} stream {} is an unknown stream type (val={})!", self.quic_conn.trace_id(), stream, stream_type);
                    },
                }
            }
        } else {
            // TODO stream frame parsing
            if stream_data.len() > 1 {
                let mut o = octets::Octets::with_slice(&mut stream_data);
                let frame = frame::H3Frame::from_bytes(&mut o).unwrap();
                debug!("received {:?}", frame);

                match frame {
                    frame::H3Frame::Headers { header_block} => {
                        //debug!("received {:?}", frame);
                        //dbg!(&header_block);

                        // TODO properly parse HEADERS
                        if &header_block[..4] == b"GET " {
                            let uri = &header_block[4..header_block.len()];
                            let uri = String::from_utf8(uri.to_vec()).unwrap();
                            let uri = String::from(uri.lines().next().unwrap());
                            let uri = std::path::Path::new(&uri);
                            let mut path = std::path::PathBuf::from(String::clone(&self.root_dir));

                            for c in uri.components() {
                                if let std::path::Component::Normal(v) = c {
                                    path.push(v)
                                }
                            }

                            info!("{} got GET request for {:?} on stream {}",
                                self.quic_conn.trace_id(), path, stream);

                            // TODO *actually* response with something other than 404
                            self.send_response(stream, String::from("404 Not Found"), String::from(""));

                        } else if &header_block[..4] == b"404 " {
                            info!("{} got 404 response on stream {}",
                                self.quic_conn.trace_id(), stream);

                            if stream_data.fin() {
                                info!("{} response received, closing..,", self.quic_conn.trace_id());
                                self.quic_conn.close(true, 0x00, b"kthxbye").unwrap();
                            }
                        }
                    },

                    _ => {
                        debug!("Not implemented!");
                    },
                };
            }
        }

    }
}

/// Creates a new client-side connection.
///
/// The `scid` parameter is used as the connection's source connection ID,
/// while the optional `server_name` parameter is used to verify the peer's
/// certificate.
pub fn connect(server_name: Option<&str>, scid: &[u8], config: &mut H3Config)
                                                -> Result<Box<H3Connection>> {


    let conn = H3Connection::new(scid, None, config, false)?;

    if server_name.is_some() {
        conn.quic_conn.tls_state.set_host_name(server_name.unwrap())
                      .map_err(|_| super::Error::TlsFail)?;
    }

    Ok(conn)
}

/// Creates a new server-side connection.
///
/// The `scid` parameter represents the server's source connection ID, while
/// the optional `odcid` parameter represents the original destination ID the
/// client sent before a stateless retry (this is only required when using
/// the [`retry()`] function).
///
/// [`retry()`]: fn.retry.html
pub fn accept(scid: &[u8], odcid: Option<&[u8]>, config: &mut H3Config) -> Result<Box<H3Connection>> {
    let conn = H3Connection::new(scid, odcid, config, true)?;

    Ok(conn)
}