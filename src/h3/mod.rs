
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

pub struct H3Config {
    pub quiche_config: super::Config,
    pub root_dir: String,
}

impl H3Config {

    /// Creates a config object with the given version.
    #[allow(clippy::new_ret_no_self)]
    pub fn new(version: u32) -> Result<H3Config> {

        Ok(H3Config {
            quiche_config: super::Config::new(version).unwrap(),
            root_dir: String::new(),
        })
    }

    pub fn set_root_dir(&mut self, root_dir: &String) {
        self.root_dir = String::clone(root_dir);
    }
}

/// An HTTP/3 connection.
pub struct H3Connection {
    pub quic_conn: Box<super::Connection>,

    root_dir: String,
}

impl H3Connection {
    #[allow(clippy::new_ret_no_self)]
    fn new(scid: &[u8], odcid: Option<&[u8]>, config: &mut H3Config,
           is_server: bool) -> Result<Box<H3Connection>> {

            let root = String::clone(&config.root_dir); // TODO shouldn't need to clone here

            Ok(Box::new(H3Connection {
                quic_conn: super::Connection::new(scid, odcid, &mut config.quiche_config, is_server)?,
                root_dir: root,
            }))
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