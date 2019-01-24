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

use crate::Result;
use crate::Error;

use crate::octets;
use crate::ranges;
use crate::stream;

use std::mem;

// H3 Settings Parameters
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SettingsParameter {
    id: u16,
    value: u64
}

//const PRIORITIZED_ELEM_TYPE_MASK: u8 = 0x30;
const ELEM_DEPENDENCY_TYPE_MASK: u8 = 0x30;

/// H3 Prioritized Element type.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum PrioritizedElemType {
    RequestStream,
    PushStream,
    Placeholder,
    CurrentStream,
}

/// H3 Element Dependency type.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ElemDependencyType {
    RequestStream,
    PushStream,
    Placeholder,
    RootOfTree,
}

#[derive(PartialEq)]
pub enum H3Frame {
    Data {
        payload: Vec<u8>,
    },

    Headers {
        header_block: Vec<u8>,
    },

    Priority {
        // TODO: parse PT and DT to determine if PEID or EDID will be present
        priority_elem: PrioritizedElemType,
        elem_dependency: ElemDependencyType,
        prioritized_element_id: u64,
        element_dependency_id: u64,
        weight: u8
    },

    CancelPush {
        push_id: u64,
    },

    Settings {
        parameters: Vec<SettingsParameter>
    },

    PushPromise {
        push_id: u64,
        header_block: Vec<u8>,
    },

    GoAway {
        stream_id: u64,
    },

    MaxPushId {
        push_id: u64,
    },

    DuplicatePush {
        push_id: u64,
    },

}

impl H3Frame {
    pub fn from_bytes(b: &mut octets::Octets) -> Result<H3Frame> {
        let payload_length = b.get_varint()?;
        let frame_type = b.get_u8()?;

        // println!("GOT FRAME {:x}", frame_type);

        // TODO handling of 0-length frames

        let frame = match frame_type {
            0x0 => H3Frame::Data {
                payload: b.get_bytes(payload_length as usize)?.to_vec(),
            },

            0x1 => H3Frame::Headers {
                header_block: b.get_bytes(payload_length as usize)?.to_vec(),
            },

            0x02 => parse_priority_frame(b)?,

            0x03 => H3Frame::CancelPush {
                push_id: b.get_varint()?,
            },

            0x04 => parse_settings_frame(payload_length, b)?,

            0x05 => parse_push_promise(payload_length, b)?,

            0x07 => H3Frame::GoAway {
                stream_id: b.get_varint()?,
            },

            0x0D => H3Frame::MaxPushId {
                push_id: b.get_varint()?,
            },

            0x0E => H3Frame::DuplicatePush {
                push_id: b.get_varint()?,
            },

            _    => return Err(Error::InvalidFrame),
        };

        Ok(frame)
    }

    pub fn to_bytes(&self, b: &mut octets::Octets) -> Result<usize> {
        let before = b.cap();

        match self {
            H3Frame::Data { payload } => {
                b.put_varint(payload.len() as u64)?;
                b.put_varint(0x00)?;

                b.put_bytes(payload.as_ref())?;
            },

            H3Frame::Headers { header_block } => {
                b.put_varint(header_block.len() as u64)?;
                b.put_varint(0x01)?;

                b.put_bytes(header_block.as_ref())?;
            },

            H3Frame::Priority { .. } => {
                // TODO: parse PT and DT to determine if PEID or EDID will be present
                // b.put_varint( length)?;
                // b.put_varint(0x02)?;

                // let mut bitfield = 0 as u8;
                // ...

                //b.put_varint(u64::from(ty))?;

                //b.put_varint(prioritized_element_id)?;
                //b.put_varint(element_dependency_id)?;
                //b.put_u8(weight)?;
            },

            H3Frame::CancelPush { push_id } => {
                b.put_varint(octets::varint_len(*push_id) as u64)?;
                b.put_varint(0x03)?;

                b.put_varint(*push_id)?;
            },

            H3Frame::Settings { parameters } => {
                // TODO make prettier
                let mut len = 0;
                for param in parameters {
                    len += mem::size_of::<u16>() + octets::varint_len(param.value);
                }

                b.put_varint(len as u64)?;
                b.put_varint(0x4)?;

                for param in parameters {
                    b.put_u16(param.id)?;
                    b.put_varint(param.value)?;
                }
            },

            H3Frame::PushPromise { push_id, header_block } => {
                let len = octets::varint_len(*push_id) + header_block.len();
                b.put_varint(len as u64)?;
                b.put_varint(0x05)?;

                b.put_varint(*push_id)?;
                b.put_bytes(header_block.as_ref())?;
            },

            H3Frame::GoAway { stream_id } => {
                b.put_varint(octets::varint_len(*stream_id) as u64)?;
                b.put_varint(0x07)?;

                b.put_varint(*stream_id)?;
            },

            H3Frame::MaxPushId { push_id } => {
                b.put_varint(octets::varint_len(*push_id) as u64)?;
                b.put_varint(0x0D)?;

                b.put_varint(*push_id)?;
            },

            H3Frame::DuplicatePush { push_id } => {
                b.put_varint(octets::varint_len(*push_id) as u64)?;
                b.put_varint(0x0E)?;

                b.put_varint(*push_id)?;
            },
        }

        Ok(before - b.cap())
    }
}

impl std::fmt::Debug for H3Frame {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            H3Frame::Data { payload } => {
                write!(f, "DATA len={}", payload.len())?;
            },

            H3Frame::Headers { header_block } => {
                write!(f, "HEADERS len={}", header_block.len())?;
            },

            H3Frame::Priority { priority_elem, elem_dependency, prioritized_element_id, element_dependency_id, weight } => {
                write!(f, "PRIORITY priority element type={:?} element dependency type={:?} prioritized element id={} element dependency id={} weight={}", priority_elem, elem_dependency, prioritized_element_id, element_dependency_id, weight)?;
            },

            H3Frame::CancelPush { push_id } => {
                write!(f, "CANCEL_PUSH push push id={}", push_id)?;
            },

            H3Frame::Settings { parameters } => {
                write!(f, "SETTINGS num params={}", parameters.len())?;
            },

            H3Frame::PushPromise { push_id, header_block } => {
                write!(f, "PUSH_PROMISE push id={} len={}", push_id, header_block.len())?;
            },

            H3Frame::GoAway { stream_id} => {
                write!(f, "GOAWAY stream id={}", stream_id)?;
            },

            H3Frame::MaxPushId { push_id } => {
                write!(f, "MAX_PUSH_ID push id={}", push_id)?;
            },

            H3Frame::DuplicatePush { push_id } => {
                write!(f, "DUPLICATE_PUSH push id={}", push_id)?;
            },
        }

        Ok(())
    }
}

fn parse_settings_frame(payload_length: u64, b: &mut octets::Octets) -> Result<H3Frame> {
    let mut parameters = Vec::new();

    while b.off() < payload_length as usize { // TODO test this exit condition
        parameters.push(SettingsParameter{ id: b.get_u16()?, value: b.get_varint()? } );
    }

    Ok(H3Frame::Settings { parameters })
}

fn parse_priority_frame(b: &mut octets::Octets) -> Result<H3Frame> {
    // TODO: parse PT and DT to determine if PEID or EDID will be present

    let bitfield = b.get_u8()?;
    let prioritized_element_id = b.get_varint()?;
    let element_dependency_id = b.get_varint()?;
    let weight = b.get_u8()?;

    let priority_elem = match (bitfield >> 6) {
        0x00 => PrioritizedElemType::RequestStream,
        0x01 => PrioritizedElemType::PushStream,
        0x02 => PrioritizedElemType::Placeholder,
        0x03 => PrioritizedElemType::CurrentStream,
        _    => return Err(Error::InvalidPacket),
    };

    let elem_dependency = match (bitfield & ELEM_DEPENDENCY_TYPE_MASK) >> 4 {
        0x00 => ElemDependencyType::RequestStream,
        0x01 => ElemDependencyType::PushStream,
        0x02 => ElemDependencyType::Placeholder,
        0x03 => ElemDependencyType::RootOfTree,
        _    => return Err(Error::InvalidPacket),
    };

    Ok(H3Frame::Priority { priority_elem,
                           elem_dependency,
                           prioritized_element_id,
                           element_dependency_id,
                           weight,
                           })
}

fn parse_push_promise(payload_length: u64, b: &mut octets::Octets) -> Result<H3Frame> {
    let push_id = b.get_varint()?;
    let header_block_length = payload_length - octets::varint_len(push_id) as u64;
    let header_block = b.get_bytes(header_block_length as usize)?.to_vec();

    Ok(H3Frame::PushPromise { push_id, header_block })
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data() {
        let mut d: [u8; 128] = [42; 128];

        let frame = H3Frame::Data {
            payload: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
        };

        let wire_len = {
            let mut b = octets::Octets::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, 14);

        {
            let mut b = octets::Octets::with_slice(&mut d);
            assert_eq!(H3Frame::from_bytes(&mut b).unwrap(), frame);
        }
    }

    #[test]
    fn headers() {
        let mut d: [u8; 128] = [42; 128];

        // TODO test QPACK'd headers
        let frame = H3Frame::Headers {
            header_block: vec![71, 69, 84, 32, 47],
        };

        let wire_len = {
            let mut b = octets::Octets::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, 7);

        {
            let mut b = octets::Octets::with_slice(&mut d);
            assert_eq!(H3Frame::from_bytes(&mut b).unwrap(), frame);
        }
    }

    /*#[test]
    fn priority() {
        // TODO: parse PT and DT to determine if PEID or EDID will be present
        let mut d: [u8; 128] = [42; 128];

        let frame = H3Frame::Priority {
            priority_elem: PrioritizedElemType::CurrentStream,
            elem_dependency: ElemDependencyType::RootOfTree,
            prioritized_element_id: 0,
            element_dependency_id: 0,
            weight: 16
        };

        let wire_len = {
            let mut b = octets::Octets::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, 17);

        {
            let mut b = octets::Octets::with_slice(&mut d);
            assert_eq!(H3Frame::from_bytes(&mut b).unwrap(), frame);
        }
    }*/

    #[test]
    fn cancel_push() {
        let mut d: [u8; 128] = [42; 128];

        let frame = H3Frame::CancelPush {
            push_id: 0
        };

        let wire_len = {
            let mut b = octets::Octets::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, 3);

        {
            let mut b = octets::Octets::with_slice(&mut d);
            assert_eq!(H3Frame::from_bytes(&mut b).unwrap(), frame);
        }
    }

    #[test]
    fn settings() {
        // TODO let mut d: [u8; 128] = [42; 128];

        assert_eq!(true, true);
    }

    #[test]
    fn push_promise() {
        let mut d: [u8; 128] = [42; 128];

        // TODO test QPACK'd headers
        let frame = H3Frame::PushPromise {
            push_id: 0,
            header_block: vec![71, 69, 84, 32, 47],
        };

        let wire_len = {
            let mut b = octets::Octets::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, 8);

        {
            let mut b = octets::Octets::with_slice(&mut d);
            assert_eq!(H3Frame::from_bytes(&mut b).unwrap(), frame);
        }
    }

    #[test]
    fn goaway() {
        let mut d: [u8; 128] = [42; 128];

        let frame = H3Frame::GoAway {
            stream_id: 32
        };

        let wire_len = {
            let mut b = octets::Octets::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, 3);

        {
            let mut b = octets::Octets::with_slice(&mut d);
            assert_eq!(H3Frame::from_bytes(&mut b).unwrap(), frame);
        }
    }

    #[test]
    fn max_push_id() {
        let mut d: [u8; 128] = [42; 128];

        let frame = H3Frame::MaxPushId {
            push_id: 128,
        };

        let wire_len = {
            let mut b = octets::Octets::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, 4);

        {
            let mut b = octets::Octets::with_slice(&mut d);
            assert_eq!(H3Frame::from_bytes(&mut b).unwrap(), frame);
        }
    }

    #[test]
    fn duplicate_push() {
        let mut d: [u8; 128] = [42; 128];

        let frame = H3Frame::DuplicatePush {
            push_id: 0
        };

        let wire_len = {
            let mut b = octets::Octets::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, 3);

        {
            let mut b = octets::Octets::with_slice(&mut d);
            assert_eq!(H3Frame::from_bytes(&mut b).unwrap(), frame);
        }
    }
}
