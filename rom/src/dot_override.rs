/*++

Licensed under the Apache-2.0 license.

File Name:

    dot_override.rs

Abstract:

    DOT override challenge/response transport using MCI mbox0.

    This module implements the `RecoveryTransport` trait using MCI mailbox 0
    to communicate with the BMC for DOT override operations.
    The BMC provides its VendorKey public keys (ECC P-384 + MLDSA-87) and signs
    a challenge with both VendorKey.priv keys.

    See docs/src/dot.md for full protocol documentation.

--*/

use core::cell::RefCell;

use caliptra_mcu_error::{McuError, McuResult};

use crate::{
    EccP384PublicKey, RecoveryTransport, MLDSA87_PUB_KEY_SIZE_DWORDS, MLDSA87_SIGNATURE_SIZE_DWORDS,
    mbox0_helpers::{CommandId, Mbox0Helpers, Mbox0Session},
};
use caliptra_mcu_registers_generated::mci;
use caliptra_mcu_romtime::StaticRef;
use tock_registers::interfaces::{ReadWriteable, Readable, Writeable};

/// Challenge type field values for DOT_UNLOCK_CHALLENGE.
pub const CHALLENGE_TYPE_UNLOCK: u32 = 0x01;
pub const CHALLENGE_TYPE_OVERRIDE: u32 = 0x02;

#[repr(C)]
struct OverrideChallengeRequest {
    chksum: u32,
    challenge_type: u32,
    ecc_pub_key_x: [u32; 12],
    ecc_pub_key_y: [u32; 12],
    mldsa_pub_key: [u32; MLDSA87_PUB_KEY_SIZE_DWORDS],
}

#[repr(C)]
struct OverrideResponse {
    chksum: u32,
    ecc_pub_key_x: [u32; 12],
    ecc_pub_key_y: [u32; 12],
    ecc_sig_r: [u32; 12],
    ecc_sig_s: [u32; 12],
    mldsa_pub_key: [u32; MLDSA87_PUB_KEY_SIZE_DWORDS],
    mldsa_signature: [u32; MLDSA87_SIGNATURE_SIZE_DWORDS],
}

/// DOT recovery transport using MCI mbox0.
pub struct Mbox0RecoveryTransport<'a> {
    helpers: &'a Mbox0Helpers,
    active_session: RefCell<Option<Mbox0Session>>,
}

impl<'a> Mbox0RecoveryTransport<'a> {
    pub fn new(helpers: &'a Mbox0Helpers) -> Self {
        Self {
            helpers,
            active_session: RefCell::new(None),
        }
    }

    /// Convert a `[u32; 12]` to `[u8; 48]` recovering the host byte order.
    fn u32x12_to_bytes(words: &[u32; 12]) -> [u8; 48] {
        let mut out = [0u8; 48];
        for i in 0..12 {
            let bytes = words[i].to_le_bytes();
            for j in 0..4 {
                out[i * 4 + j] = bytes[j];
            }
        }
        out
    }
}

impl<'a> RecoveryTransport for Mbox0RecoveryTransport<'a> {
    fn wait_for_override_request(&self) -> McuResult<crate::OverrideRequest<'_>> {
        let session = self.helpers.wait_for_mbox0_cmd();
        if session.cmd() != CommandId::DOT_UNLOCK_CHALLENGE {
            caliptra_mcu_romtime::println!(
                "[dot-override] Unexpected mbox0 cmd: {:#x}, expected DOT_UNLOCK_CHALLENGE",
                session.cmd().0
            );
            return Err(McuError::ROM_DOT_OVERRIDE_CHALLENGE_FAILED);
        }

        let dlen = session.dlen();
        if dlen < core::mem::size_of::<OverrideChallengeRequest>() {
            caliptra_mcu_romtime::println!("[dot-override] DOT_UNLOCK_CHALLENGE dlen too small");
            return Err(McuError::ROM_DOT_OVERRIDE_CHALLENGE_FAILED);
        }
        if !session.verify_checksum() {
            caliptra_mcu_romtime::println!("[dot-override] DOT_UNLOCK_CHALLENGE checksum failed");
            return Err(McuError::ROM_DOT_OVERRIDE_CHALLENGE_FAILED);
        }

        let req = unsafe { session.sram_as::<OverrideChallengeRequest>() };

        if req.challenge_type != CHALLENGE_TYPE_OVERRIDE {
            caliptra_mcu_romtime::println!(
                "[dot-override] Unsupported challenge_type: {:#x}, expected OVERRIDE ({:#x})",
                req.challenge_type,
                CHALLENGE_TYPE_OVERRIDE
            );
            return Err(McuError::ROM_DOT_OVERRIDE_CHALLENGE_FAILED);
        }

        let ecc_pub_key = EccP384PublicKey {
            x: req.ecc_pub_key_x,
            y: req.ecc_pub_key_y,
        };
        let mldsa_pub_key = &req.mldsa_pub_key;

        caliptra_mcu_romtime::println!(
            "[dot-override] Override challenge request received via mbox0"
        );

        *self.active_session.borrow_mut() = Some(session);

        Ok(crate::OverrideRequest {
            ecc_pub_key,
            mldsa_pub_key,
        })
    }

    fn send_challenge(&self, challenge: &[u8; 48]) -> McuResult<()> {
        caliptra_mcu_romtime::println!("[dot-override] Sending challenge via mbox0");
        let mut session = self.active_session.borrow_mut().take().ok_or(
            McuError::ROM_DOT_OVERRIDE_CHALLENGE_FAILED,
        )?;
        session.send_mbox0_response(challenge);
        Ok(())
    }

    fn receive_override_response(&self) -> McuResult<crate::OverrideChallengeResponse<'_>> {
        let mut session = self.helpers.wait_for_mbox0_cmd();
        if session.cmd() != CommandId::DOT_OVERRIDE {
            caliptra_mcu_romtime::println!(
                "[dot-override] Unexpected mbox0 cmd: {:#x}, expected DOT_OVERRIDE",
                session.cmd().0
            );
            return Err(McuError::ROM_DOT_OVERRIDE_CHALLENGE_FAILED);
        }

        let dlen = session.dlen();
        if dlen < core::mem::size_of::<OverrideResponse>() {
            caliptra_mcu_romtime::println!("[dot-override] DOT_OVERRIDE dlen too small");
            return Err(McuError::ROM_DOT_OVERRIDE_CHALLENGE_FAILED);
        }
        if !session.verify_checksum() {
            caliptra_mcu_romtime::println!("[dot-override] DOT_OVERRIDE checksum failed");
            return Err(McuError::ROM_DOT_OVERRIDE_CHALLENGE_FAILED);
        }

        let resp = unsafe { session.sram_as::<OverrideResponse>() };
        let ecc_pub_key = EccP384PublicKey {
            x: resp.ecc_pub_key_x,
            y: resp.ecc_pub_key_y,
        };
        let ecc_signature_r = Self::u32x12_to_bytes(&resp.ecc_sig_r);
        let ecc_signature_s = Self::u32x12_to_bytes(&resp.ecc_sig_s);
        let mldsa_pub_key = &resp.mldsa_pub_key;
        let mldsa_signature = &resp.mldsa_signature;

        caliptra_mcu_romtime::println!("[dot-override] Override response received via mbox0");
        session.success();

        Ok(crate::OverrideChallengeResponse {
            ecc_pub_key,
            ecc_signature_r,
            ecc_signature_s,
            mldsa_signature,
            mldsa_pub_key,
        })
    }

    fn abort_pending_session(&self) {
        self.active_session.borrow_mut().take();
    }
}
