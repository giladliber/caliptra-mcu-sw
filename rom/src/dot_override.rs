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

use caliptra_mcu_error::{McuError, McuResult};

use crate::{
    EccP384PublicKey, RecoveryTransport, MLDSA87_PUB_KEY_SIZE_DWORDS, MLDSA87_SIGNATURE_SIZE_DWORDS,
    mbox0_helpers::Mbox0Helpers,
};
use caliptra_mcu_registers_generated::mci;
use caliptra_mcu_romtime::StaticRef;
use tock_registers::interfaces::{ReadWriteable, Readable, Writeable};

pub const CMD_DOT_UNLOCK_CHALLENGE: u32 = 0x444F_5457;
pub const CMD_DOT_OVERRIDE: u32 = 0x444F_5458;

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
}

impl<'a> Mbox0RecoveryTransport<'a> {
    pub fn new(helpers: &'a Mbox0Helpers) -> Self {
        Self { helpers }
    }
}

impl<'a> RecoveryTransport for Mbox0RecoveryTransport<'a> {
    fn wait_for_override_request(&self) -> McuResult<crate::OverrideRequest<'_>> {
        let cmd = self.helpers.wait_for_mbox0_cmd();
        if cmd != CMD_DOT_UNLOCK_CHALLENGE {
            caliptra_mcu_romtime::println!(
                "[dot-override] Unexpected mbox0 cmd: {:#x}, expected DOT_UNLOCK_CHALLENGE",
                cmd
            );
            self.helpers.cmd_failure();
            return Err(McuError::ROM_DOT_OVERRIDE_CHALLENGE_FAILED);
        }

        let dlen = self.helpers.dlen();
        if dlen < core::mem::size_of::<OverrideChallengeRequest>() {
            caliptra_mcu_romtime::println!("[dot-override] DOT_UNLOCK_CHALLENGE dlen too small");
            self.helpers.cmd_failure();
            return Err(McuError::ROM_DOT_OVERRIDE_CHALLENGE_FAILED);
        }
        if !self.helpers.verify_checksum(cmd, dlen) {
            caliptra_mcu_romtime::println!("[dot-override] DOT_UNLOCK_CHALLENGE checksum failed");
            self.helpers.cmd_failure();
            return Err(McuError::ROM_DOT_OVERRIDE_CHALLENGE_FAILED);
        }

        let req = unsafe { self.helpers.sram_as::<OverrideChallengeRequest>() };

        if req.challenge_type != CHALLENGE_TYPE_OVERRIDE {
            caliptra_mcu_romtime::println!(
                "[dot-override] Unsupported challenge_type: {:#x}, expected OVERRIDE ({:#x})",
                req.challenge_type,
                CHALLENGE_TYPE_OVERRIDE
            );
            self.helpers.cmd_failure();
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

        Ok(crate::OverrideRequest {
            ecc_pub_key,
            mldsa_pub_key,
        })
    }

    fn send_challenge(&self, challenge: &[u8; 48]) -> McuResult<()> {
        caliptra_mcu_romtime::println!("[dot-override] Sending challenge via mbox0");
        self.helpers.send_mbox0_response(challenge);
        Ok(())
    }

    fn receive_override_response(&self) -> McuResult<crate::OverrideChallengeResponse<'_>> {
        let cmd = self.helpers.wait_for_mbox0_cmd();
        if cmd != CMD_DOT_OVERRIDE {
            caliptra_mcu_romtime::println!(
                "[dot-override] Unexpected mbox0 cmd: {:#x}, expected DOT_OVERRIDE",
                cmd
            );
            self.helpers.cmd_failure();
            return Err(McuError::ROM_DOT_OVERRIDE_CHALLENGE_FAILED);
        }

        let dlen = self.helpers.dlen();
        if dlen < core::mem::size_of::<OverrideResponse>() {
            caliptra_mcu_romtime::println!("[dot-override] DOT_OVERRIDE dlen too small");
            self.helpers.cmd_failure();
            return Err(McuError::ROM_DOT_OVERRIDE_CHALLENGE_FAILED);
        }
        if !self.helpers.verify_checksum(cmd, dlen) {
            caliptra_mcu_romtime::println!("[dot-override] DOT_OVERRIDE checksum failed");
            self.helpers.cmd_failure();
            return Err(McuError::ROM_DOT_OVERRIDE_CHALLENGE_FAILED);
        }

        let resp = unsafe { self.helpers.sram_as::<OverrideResponse>() };
        let ecc_pub_key = EccP384PublicKey {
            x: resp.ecc_pub_key_x,
            y: resp.ecc_pub_key_y,
        };
        let ecc_signature_r = Mbox0Helpers::u32x12_to_bytes(&resp.ecc_sig_r);
        let ecc_signature_s = Mbox0Helpers::u32x12_to_bytes(&resp.ecc_sig_s);
        let mldsa_pub_key = &resp.mldsa_pub_key;
        let mldsa_signature = &resp.mldsa_signature;

        caliptra_mcu_romtime::println!("[dot-override] Override response received via mbox0");

        Ok(crate::OverrideChallengeResponse {
            ecc_pub_key,
            ecc_signature_r,
            ecc_signature_s,
            mldsa_signature,
            mldsa_pub_key,
        })
    }
}
