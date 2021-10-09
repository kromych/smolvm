#![allow(dead_code)]

/*
    PL011 Registers:

    Offset  Name              Type Reset        Bits    Description
    ----------------------------------------------------------------------
    0x000   UARTDR            RW   0x---        12/8    Data Register
    0x004   UARTRSR/UARTECR   RW   0x0          4/0     Receive Status Register/Error Clear Register
    0x018   UARTFR            RO   0b-10010---  9       Flag Register
    0x020   UARTILPR          RW   0x00         8       IrDA Low-Power Counter Register
    0x024   UARTIBRD          RW   0x0000       16      Integer Baud Rate Register
    0x028   UARTFBRD          RW   0x00         6       Fractional Baud Rate Register
    0x02C   UARTLCR_H         RW   0x00         8       Line Control Register
    0x030   UARTCR            RW   0x0300       16      Control Register
    0x034   UARTIFLS          RW   0x12         6       Interrupt FIFO Level Select Register
    0x038   UARTIMSC          RW   0x000        11      Interrupt Mask Set/Clear Register
    0x03C   UARTRIS           RO   0x00-        11      Raw Interrupt Status Register
    0x040   UARTMIS           RO   0x00-        11      Masked Interrupt Status Register
    0x044   UARTICR           WO   -            11      Interrupt Clear Register
    0x048   UARTDMACR         RW   0x00         3       DMA Control Register
    0xFE0   UARTPeriphID0     RO   0x11         8       UARTPeriphID0 Register
    0xFE4   UARTPeriphID1     RO   0x10         8       UARTPeriphID1 Register
    0xFE8   UARTPeriphID2     RO   0x_4a        8       UARTPeriphID2 Register
    0xFEC   UARTPeriphID3     RO   0x00         8       UARTPeriphID3 Register
    0xFF0   UARTPCellID0      RO   0x0D         8       UARTPCellID0 Register
    0xFF4   UARTPCellID1      RO   0xF0         8       UARTPCellID1 Register
    0xFF8   UARTPCellID2      RO   0x05         8       UARTPCellID2 Register
    0xFFC   UARTPCellID3      RO   0xB1         8       UARTPCellID3 Register
*/

use zerocopy::AsBytes;

const UART_DR: usize = 0x000;
const UART_RSR: usize = 0x004;
const UART_FR: usize = 0x018;
const UART_ILPR: usize = 0x020;
const UART_IBRD: usize = 0x024;
const UART_FBRD: usize = 0x028;
const UART_LCR_H: usize = 0x02C;
const UART_CR: usize = 0x030;
const UART_IFLS: usize = 0x034;
const UART_IMSC: usize = 0x038;
const UART_RIS: usize = 0x03C;
const UART_MIS: usize = 0x040;
const UART_ICR: usize = 0x044;
const UART_DMACR: usize = 0x048;

const UART_PERIPH_ID0: usize = 0xFE0;
const UART_PERIPH_ID1: usize = 0xFE4;
const UART_PERIPH_ID2: usize = 0xFE8;
const UART_PERIPH_ID3: usize = 0xFEC;
const UART_PCELL_ID0: usize = 0xFF0;
const UART_PCELL_ID1: usize = 0xFF4;
const UART_PCELL_ID2: usize = 0xFF8;
const UART_PCELL_ID3: usize = 0xFFC;

const UART_CR_RX_ENABLE: u32 = 1 << 9;
const UART_CR_TX_ENABLE: u32 = 1 << 8;
const UART_CR_UART_ENABLE: u32 = 1;

const UART_LCR_H_FIFO_EN: u32 = 1 << 4;
const UART_LCR_H_8BITS: u32 = 3 << 5;

const UART_FR_TX_EMPTY: u32 = 1 << 7;
const UART_FR_RX_EMPTY: u32 = 1 << 4;
const UART_FR_UART_BUSY: u32 = 1 << 3;

const UARTIFLS_RX_HALF_FULL: u32 = 0b010 << 3;
const UARTIFLS_TX_HALF_FULL: u32 = 0b010;

enum Pl011Access {
    Read,
    Write,
}

pub struct UartPl011 {
    base_addr: u64,
    registers: Vec<u32>,
    id: [u8; 8],
    buffer: Vec<u8>,
}

impl UartPl011 {
    pub fn new(base_addr: u64) -> Self {
        let mut registers = vec![0_u32; 0x48];

        registers[UART_FR >> 2] = UART_FR_RX_EMPTY | UART_FR_TX_EMPTY;
        registers[UART_CR >> 2] = UART_CR_RX_ENABLE | UART_CR_TX_ENABLE;
        registers[UART_IFLS >> 2] = UARTIFLS_RX_HALF_FULL | UARTIFLS_TX_HALF_FULL;

        let id = [0x11, 0x10, 0x4a, 0x00, 0x0D, 0xF0, 0x05, 0xB1];

        Self {
            base_addr,
            registers,
            id,
            buffer: Vec::with_capacity(512),
        }
    }

    pub fn read(&mut self, addr: u64) -> Option<u32> {
        if let Some(offset) = self.get_offset(addr) {
            if let Some(mask) = Self::check_access_and_get_mask(Pl011Access::Read, offset) {
                if offset >= UART_PERIPH_ID0 {
                    Some(self.id[(offset - UART_PERIPH_ID0) >> 2] as u32 & mask)
                } else {
                    Some(self.registers[offset >> 2] & mask)
                }
            } else {
                log::warn!("Unsupported MMIO read from 0x{:x}", addr);
                None
            }
        } else {
            log::warn!("Unknown MMIO read from 0x{:x}", addr);
            None
        }
    }

    pub fn write(&mut self, addr: u64, value: u32) {
        if let Some(offset) = self.get_offset(addr) {
            if let Some(mask) = Self::check_access_and_get_mask(Pl011Access::Write, offset) {
                self.registers[offset >> 2] = value & mask;
                if offset == 0 {
                    self.buffer.push(value as u8);

                    if value == b'\n' as u32 {
                        use std::io::Write;

                        print!("{}", unsafe {
                            std::str::from_utf8_unchecked(self.buffer.as_bytes())
                        });
                        std::io::stdout().flush().ok();
                        self.buffer.clear();
                    }
                }
            } else {
                log::warn!("Unsupported MMIO write to 0x{:x}", addr);
            }
        } else {
            log::warn!("Unknown MMIO write to 0x{:x}", addr);
        }
    }

    fn get_offset(&self, addr: u64) -> Option<usize> {
        if addr < self.base_addr {
            return None;
        }

        match (addr - self.base_addr) as usize {
            UART_DR => Some(UART_DR),
            UART_RSR => Some(UART_RSR),
            UART_FR => Some(UART_FR),
            UART_ILPR => Some(UART_ILPR),
            UART_IBRD => Some(UART_IBRD),
            UART_FBRD => Some(UART_FBRD),
            UART_LCR_H => Some(UART_LCR_H),
            UART_CR => Some(UART_CR),
            UART_IFLS => Some(UART_IFLS),
            UART_IMSC => Some(UART_IMSC),
            UART_RIS => Some(UART_RIS),
            UART_MIS => Some(UART_MIS),
            UART_ICR => Some(UART_ICR),
            UART_DMACR => Some(UART_DMACR),
            UART_PERIPH_ID0 => Some(UART_PERIPH_ID0),
            UART_PERIPH_ID1 => Some(UART_PERIPH_ID1),
            UART_PERIPH_ID2 => Some(UART_PERIPH_ID2),
            UART_PERIPH_ID3 => Some(UART_PERIPH_ID3),
            UART_PCELL_ID0 => Some(UART_PCELL_ID0),
            UART_PCELL_ID1 => Some(UART_PCELL_ID1),
            UART_PCELL_ID2 => Some(UART_PCELL_ID2),
            UART_PCELL_ID3 => Some(UART_PCELL_ID3),
            _ => None,
        }
    }

    fn check_access_and_get_mask(access: Pl011Access, offset: usize) -> Option<u32> {
        match access {
            Pl011Access::Read => match offset {
                // Read-only
                UART_FR => Some(0x1ff),
                UART_MIS => Some(0x7ff),
                UART_PCELL_ID0 => Some(0xff),
                UART_PCELL_ID1 => Some(0xff),
                UART_PCELL_ID2 => Some(0xff),
                UART_PCELL_ID3 => Some(0xff),
                UART_PERIPH_ID0 => Some(0xff),
                UART_PERIPH_ID1 => Some(0xff),
                UART_PERIPH_ID2 => Some(0xff),
                UART_PERIPH_ID3 => Some(0xff),
                UART_RIS => Some(0x7ff),
                // Available for write
                UART_CR => Some(0xffff),
                UART_DMACR => Some(3),
                UART_DR => Some(0xff),
                UART_FBRD => Some(0x3f),
                UART_IBRD => Some(0xffff),
                UART_IFLS => Some(0x3f),
                UART_ILPR => Some(0xff),
                UART_IMSC => Some(0x7ff),
                UART_LCR_H => Some(0xff),
                UART_RSR => Some(0xf),
                //UART_ICR => Some(0x7ff), // Write-only
                _ => None,
            },
            Pl011Access::Write => match offset {
                UART_CR => Some(0xffff),
                UART_DMACR => Some(3),
                UART_DR => Some(0xff),
                UART_FBRD => Some(0x3f),
                UART_IBRD => Some(0xffff),
                UART_IFLS => Some(0x3f),
                UART_ILPR => Some(0xff),
                UART_IMSC => Some(0x7ff),
                UART_LCR_H => Some(0xff),
                UART_RSR => Some(0xf),
                UART_ICR => Some(0x7ff), // Write-only
                _ => None,
            },
        }
    }
}
