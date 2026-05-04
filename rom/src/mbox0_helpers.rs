/*++

Licensed under the Apache-2.0 license.

File Name:

    mbox0_helpers.rs

Abstract:

    MCI mailbox 0 helper utilities for DOT operations.

    Provides low-level access to MCI mbox0 registers and SRAM for
    challenge/response communication with the BMC.

--*/

use caliptra_mcu_registers_generated::mci;
use caliptra_mcu_romtime::StaticRef;
use tock_registers::interfaces::{ReadWriteable, Readable, Writeable};
use core::convert::From;

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

#[derive(Clone, Copy)]
enum SessionStatus {
    DataReady,
    CmdComplete,
    CmdFailure,
}

pub struct Mbox0Session {
    mci: StaticRef<mci::regs::Mci>,
    cmd: CommandId,
    status: SessionStatus,
}

impl Mbox0Session {
    pub fn cmd(&self) -> CommandId {
        self.cmd
    }

    pub fn dlen(&self) -> usize {
        self.mci.mcu_mbox0_csr_mbox_dlen.get() as usize
    }

    pub fn verify_checksum(&self) -> bool {
        let sram = &self.mci.mcu_mbox0_csr_mbox_sram;
        let sram = unsafe { core::slice::from_raw_parts(sram.as_ptr() as *const u32, sram.len()) };
        let stored_checksum = match sram.first() {
            Some(&v) => v,
            None => return false,
        };

        let mut sum = 0u32;
        for b in u32::from(self.cmd).to_le_bytes() {
            sum = sum.wrapping_add(b as u32);
        }
        let dlen = self.dlen();
        let payload_len = if dlen > 4 { dlen - 4 } else { 0 };
        let payload_words = payload_len.div_ceil(4).min(sram.len().saturating_sub(1));
        for i in 0..payload_words {
            if let Some(&word) = sram.get(i + 1) {
                for b in word.to_le_bytes() {
                    sum = sum.wrapping_add(b as u32);
                }
            }
        }

        stored_checksum == 0u32.wrapping_sub(sum)
    }

    /// # Safety
    /// Caller must ensure the SRAM contains a valid `T` at offset 0.
    pub unsafe fn sram_as<T>(&self) -> &'static T {
        &*(self.mci.mcu_mbox0_csr_mbox_sram.as_ptr() as *const T)
    }

    pub fn send_mbox0_response(mut self, data: &[u8]) {
        let sram = &self.mci.mcu_mbox0_csr_mbox_sram;
        let sram =
            unsafe { core::slice::from_raw_parts_mut(sram.as_ptr() as *mut u32, sram.len()) };
        let len_words = data.len().div_ceil(4).min(sram.len());
        for i in 0..len_words {
            let byte_off = i * 4;
            let mut word_bytes = [0u8; 4];
            for (j, wb) in word_bytes.iter_mut().enumerate() {
                if let Some(&b) = data.get(byte_off + j) {
                    *wb = b;
                }
            }
            if let Some(w) = sram.get_mut(i) {
                *w = u32::from_le_bytes(word_bytes);
            }
        }
        self.mci.mcu_mbox0_csr_mbox_dlen.set(data.len() as u32);
        self.status = SessionStatus::DataReady;
    }

    pub fn success(mut self) {
        self.status = SessionStatus::CmdComplete;
    }
}

impl Drop for Mbox0Session {
    fn drop(&mut self) {
        let status = match self.status {
            SessionStatus::DataReady => mci::bits::MboxCmdStatus::Status::DataReady,
            SessionStatus::CmdComplete => mci::bits::MboxCmdStatus::Status::CmdComplete,
            SessionStatus::CmdFailure => mci::bits::MboxCmdStatus::Status::CmdFailure,
        };
        self.mci.mcu_mbox0_csr_mbox_cmd_status.write(status);
    }
}

/// MCI mbox0 helpers for the override transport.
#[derive(Clone, Copy)]
pub struct Mbox0Helpers {
    mci: StaticRef<mci::regs::Mci>,
}

impl Mbox0Helpers {
    pub fn new(mci: StaticRef<mci::regs::Mci>) -> Self {
        mci.intr_block_rf_notif0_intr_en_r
            .modify(mci::bits::Notif0IntrEnT::NotifMbox0CmdAvailEn::SET);
        Self { mci }
    }

    pub fn wait_for_mbox0_cmd(&self) -> Mbox0Session {
        let notif0 = &self.mci.intr_block_rf_notif0_internal_intr_r;
        while notif0.read(mci::bits::Notif0IntrT::NotifMbox0CmdAvailSts) == 0 {}
        notif0.modify(mci::bits::Notif0IntrT::NotifMbox0CmdAvailSts::SET);
        Mbox0Session {
            mci: self.mci,
            cmd: self.mci.mcu_mbox0_csr_mbox_cmd.get().into(),
            status: SessionStatus::CmdFailure,
        }
    }
}
