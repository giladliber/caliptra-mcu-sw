/*++

Licensed under the Apache-2.0 license.

File Name:

    mailbox_messages.rs

Abstract:

    Mailbox message identifiers and wire formats used by ROM mailbox helpers.

--*/

use crate::{MLDSA87_PUB_KEY_SIZE_DWORDS, MLDSA87_SIGNATURE_SIZE_DWORDS};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub struct CommandId(pub u32);

impl CommandId {
    pub const DOT_UNLOCK_CHALLENGE: Self = Self(0x444F_5457);
    pub const DOT_OVERRIDE: Self = Self(0x444F_5458);
}

impl From<u32> for CommandId {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl From<CommandId> for u32 {
    fn from(value: CommandId) -> Self {
        value.0
    }
}

pub trait MailboxResponse: IntoBytes + FromBytes + Immutable + KnownLayout {}

pub trait MailboxRequest: IntoBytes + FromBytes + Immutable + KnownLayout {
    const COMMAND_ID: CommandId;
    type Response: MailboxResponse;
}

#[derive(Clone, Copy, Debug, Default, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct NoResponse {
    _reserved: [u8; 0],
}

#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct OverrideChallenge {
    pub challenge: [u8; 48],
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct Ecc384Words(pub [u32; 12]);

impl Ecc384Words {
    pub fn to_bytes(&self) -> [u8; 48] {
        let mut out = [0u8; 48];
        for (index, word) in self.0.iter().enumerate() {
            let bytes = word.to_le_bytes();
            out[index * 4..(index + 1) * 4].copy_from_slice(&bytes);
        }
        out
    }
}

impl From<[u32; 12]> for Ecc384Words {
    fn from(value: [u32; 12]) -> Self {
        Self(value)
    }
}

impl From<Ecc384Words> for [u32; 12] {
    fn from(value: Ecc384Words) -> Self {
        value.0
    }
}

#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct OverrideChallengeRequest {
    pub chksum: u32,
    pub challenge_type: u32,
    pub ecc_pub_key_x: Ecc384Words,
    pub ecc_pub_key_y: Ecc384Words,
    pub mldsa_pub_key: [u32; MLDSA87_PUB_KEY_SIZE_DWORDS],
}

impl MailboxRequest for OverrideChallengeRequest {
    const COMMAND_ID: CommandId = CommandId::DOT_UNLOCK_CHALLENGE;
    type Response = OverrideChallenge;
}

#[derive(Clone, Copy, Debug, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct OverrideResponse {
    pub chksum: u32,
    pub ecc_pub_key_x: Ecc384Words,
    pub ecc_pub_key_y: Ecc384Words,
    pub ecc_sig_r: Ecc384Words,
    pub ecc_sig_s: Ecc384Words,
    pub mldsa_pub_key: [u32; MLDSA87_PUB_KEY_SIZE_DWORDS],
    pub mldsa_signature: [u32; MLDSA87_SIGNATURE_SIZE_DWORDS],
}

impl MailboxRequest for OverrideResponse {
    const COMMAND_ID: CommandId = CommandId::DOT_OVERRIDE;
    type Response = NoResponse;
}

