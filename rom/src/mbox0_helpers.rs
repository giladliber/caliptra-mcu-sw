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

    /// # Safety
    /// Caller must ensure the SRAM contains a valid `T` at offset 0.
    pub unsafe fn sram_as<T>(&self) -> &T {
        &*(self.mci.mcu_mbox0_csr_mbox_sram.as_ptr() as *const T)
    }

    /// Convert a `[u32; 12]` to `[u8; 48]` recovering the host byte order.
    pub fn u32x12_to_bytes(words: &[u32; 12]) -> [u8; 48] {
        let mut out = [0u8; 48];
        for i in 0..12 {
            let bytes = words[i].to_le_bytes();
            for j in 0..4 {
                out[i * 4 + j] = bytes[j];
            }
        }
        out
    }

    pub fn verify_checksum(&self, cmd: u32, dlen: usize) -> bool {
        let sram = &self.mci.mcu_mbox0_csr_mbox_sram;
        let sram = unsafe { core::slice::from_raw_parts(sram.as_ptr() as *const u32, sram.len()) };
        let stored_checksum = match sram.first() {
            Some(&v) => v,
            None => return false,
        };

        let mut sum = 0u32;
        for b in cmd.to_le_bytes() {
            sum = sum.wrapping_add(b as u32);
        }
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

    pub fn wait_for_mbox0_cmd(&self) -> u32 {
        let notif0 = &self.mci.intr_block_rf_notif0_internal_intr_r;
        while notif0.read(mci::bits::Notif0IntrT::NotifMbox0CmdAvailSts) == 0 {}
        notif0.modify(mci::bits::Notif0IntrT::NotifMbox0CmdAvailSts::SET);
        self.mci.mcu_mbox0_csr_mbox_cmd.get()
    }

    pub fn send_mbox0_response(&self, data: &[u8]) {
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
        self.mci
            .mcu_mbox0_csr_mbox_cmd_status
            .write(mci::bits::MboxCmdStatus::Status::DataReady);
    }

    pub fn cmd_failure(&self) {
        self.mci
            .mcu_mbox0_csr_mbox_cmd_status
            .write(mci::bits::MboxCmdStatus::Status::CmdFailure);
    }

    pub fn dlen(&self) -> usize {
        self.mci.mcu_mbox0_csr_mbox_dlen.get() as usize
    }
}
