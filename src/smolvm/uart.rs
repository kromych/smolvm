#![allow(dead_code)]

//!
//!  COM1 COM2 COM3 COM4 Offs. DLAB  Register
//!  ------------------------------------------------------------------------------
//!  3F8h 2F8h 3E8h 2E8h  +0     0   RBR  Receive Buffer Register (read only) or
//!                                  THR  Transmitter Holding Register (write only)
//!  3F9h 2F9h 3E9h 2E9h  +1     0   IER  Interrupt Enable Register
//!  3F8h 2F8h 3E8h 2E8h  +0     1   DL   Divisor Latch (LSB)  These registers can
//!  3F9h 2F9h 3E9h 2E9h  +1     1   DL   Divisor Latch (MSB)  be accessed as word
//!  3FAh 2FAh 3EAh 2EAh  +2     x   IIR  Interrupt Identification Register (r/o) or
//!                                  FCR  FIFO Control Register (w/o, 16550+ only)
//!  3FBh 2FBh 3EBh 2EBh  +3     x   LCR  Line Control Register
//!  3FCh 2FCh 3ECh 2ECh  +4     x   MCR  Modem Control Register
//!  3FDh 2FDh 3EDh 2EDh  +5     x   LSR  Line Status Register
//!  3FEh 2FEh 3EEh 2EEh  +6     x   MSR  Modem Status Register
//!  3FFh 2FFh 3EFh 2EFh  +7     x   SCR  Scratch Register (16450+ and some 8250s,
//!                                      special use with some boards)
//!  
//!            80h      40h      20h      10h      08h      04h      02h      01h
//!  Register  Bit 7    Bit 6    Bit 5    Bit 4    Bit 3    Bit 2    Bit 1    Bit 0
//!  -------------------------------------------------------------------------------
//!  IER         0        0        0        0      EDSSI    ELSI     ETBEI    ERBFI
//!  IIR (r/o) FIFO en  FIFO en    0        0      IID2     IID1     IID0    pending
//!  FCR (w/o)  - RX trigger -     0        0      DMA sel  XFres    RFres   enable
//!  LCR       DLAB     SBR    stick par  even sel Par en  stopbits  - word length -
//!  MCR         0        0        0      Loop     OUT2     OUT1     RTS     DTR
//!  LSR       FIFOerr  TEMT     THRE     Break    FE       PE       OE      RBF
//!  MSR       DCD      RI       DSR      CTS      DDCD     TERI     DDSR    DCTS
//!  
//!  EDSSI:       Enable Delta Status Signals Interrupt
//!  ELSI:        Enable Line Status Interrupt
//!  ETBEI:       Enable Transmitter Buffer Empty Interrupt
//!  ERBFI:       Enable Receiver Buffer Full Interrupt
//!  FIFO en:     FIFO enable
//!  IID#:        Interrupt IDentification
//!  pending:     an interrupt is pending if '0'
//!  RX trigger:  RX FIFO trigger level select
//!  DMA sel:     DMA mode select
//!  XFres:       Transmitter FIFO reset
//!  RFres:       Receiver FIFO reset
//!  DLAB:        Divisor Latch Access Bit
//!  SBR:         Set BReak
//!  stick par:   Stick Parity select
//!  even sel:    Even Parity select
//!  stopbits:    Stop bit select
//!  word length: Word length select
//!  FIFOerr:     At least one error is pending in the RX FIFO chain
//!  TEMT:        Transmitter Empty (last word has been sent)
//!  THRE:        Transmitter Holding Register Empty (new data can be written to THR)
//!  Break:       Broken line detected
//!  FE:          Framing Error
//!  PE:          Parity Error
//!  OE:          Overrun Error
//!  RBF:         Receiver Buffer Full (Data Available)
//!  DCD:         Data Carrier Detect
//!  RI:          Ring Indicator
//!  DSR:         Data Set Ready
//!  CTS:         Clear To Send
//!  DDCD:        Delta Data Carrier Detect
//!  TERI:        Trailing Edge Ring Indicator
//!  DDSR:        Delta Data Set Ready
//!  DCTS:        Delta Clear To Send
//!

use zerocopy::AsBytes;

pub enum UartBase {
    Com1,
    Com2,
    Com3,
    Com4,
}

const BAUD_9600: u16 = 0xC;
const BAUD_19200: u16 = 0x6;
const BAUD_38400: u16 = 0x3;
const BAUD_57600: u16 = 0x2;
const BAUD_115200: u16 = 0x1;

const RBR_THR_OFFSET: u8 = 0;
const IER_OFFSET: u8 = 1;
const IIR_FCR_OFFSET: u8 = 2;
const LCR_OFFSET: u8 = 3;
const MCR_OFFSET: u8 = 4;
const LSR_OFFSET: u8 = 5;
const MSR_OFFSET: u8 = 6;
const SCR_OFFSET: u8 = 7;

#[derive(Default)]
pub struct Uart {
    base_addr: u16,
    divisor_latch: [u8; 2],
    registers: [u8; 8],
    buffer: Vec<u8>,
}

impl Uart {
    pub fn new(base: UartBase) -> Self {
        let mut uart = Self {
            base_addr: match base {
                UartBase::Com1 => 0x3F8,
                UartBase::Com2 => 0x2F8,
                UartBase::Com3 => 0x3E8,
                UartBase::Com4 => 0x2E8,
            },
            buffer: Vec::with_capacity(512),
            ..Default::default()
        };

        uart.can_send();
        uart.can_receive();

        uart
    }

    pub fn write_byte(&mut self, address: u16, data: u8) {
        self.can_send();
        self.can_receive();

        if self.divisor_latch_active() {
            if address == self.base_addr {
                self.divisor_latch[0] = data;
                return;
            } else if address == self.base_addr + 1 {
                self.divisor_latch[1] = data;
                return;
            }
        }

        if let Some(offset) = self.register_offset(address) {
            self.registers[offset] = data;
            if offset == 0 {
                self.buffer.push(data);

                if data == b'\n' {
                    use std::io::Write;

                    print!("{}", unsafe {
                        std::str::from_utf8_unchecked(self.buffer.as_bytes())
                    });
                    std::io::stdout().flush().ok();
                    self.buffer.clear();
                }
            }
        } else {
            log::warn!(
                "Writing {} at to {:#x}, base {:#x}, not implemented",
                data,
                address,
                self.base_addr
            )
        }
    }

    pub fn write_word(&mut self, address: u16, data: u16) {
        self.can_send();
        self.can_receive();

        if self.divisor_latch_active() {
            if address == self.base_addr {
                self.divisor_latch[0] = (data & 0xff) as u8;
                self.divisor_latch[1] = (data >> 8) as u8;

                return;
            }
        }

        if let Some(offset) = self.register_offset(address) {
            self.registers[offset] = data as u8 & 0xff;
        } else {
            log::warn!(
                "Writing {} at to {:#x}, base {:#x}, not implemented",
                data,
                address,
                self.base_addr
            )
        }
    }

    pub fn read_byte(&mut self, address: u16) -> Option<u8> {
        self.can_send();
        self.can_receive();

        if self.divisor_latch_active() {
            if address == self.base_addr {
                return Some(self.divisor_latch[0]);
            } else if address == self.base_addr + 1 {
                return Some(self.divisor_latch[1]);
            }
        }

        if let Some(offset) = self.register_offset(address) {
            Some(self.registers[offset])
        } else {
            log::warn!(
                "Reading from {:#x}, base {:#x}, not implemented",
                address,
                self.base_addr
            );

            None
        }
    }

    pub fn read_word(&mut self, address: u16) -> Option<u16> {
        self.can_send();
        self.can_receive();

        if self.divisor_latch_active() {
            if address == self.base_addr {
                return Some(self.divisor_latch[0] as u16 | ((self.divisor_latch[1] as u16) << 8));
            }
        }

        if let Some(offset) = self.register_offset(address) {
            Some(self.registers[offset] as u16)
        } else {
            log::warn!(
                "Reading from {:#x}, base {:#x}, not implemented",
                address,
                self.base_addr
            );

            None
        }
    }

    fn divisor_latch_active(&self) -> bool {
        self.registers[LCR_OFFSET as usize] & 0x80 != 0
    }

    fn register_offset(&self, address: u16) -> Option<usize> {
        if address >= self.base_addr && address < self.base_addr + self.registers.len() as u16 {
            Some((address - self.base_addr) as usize)
        } else {
            None
        }
    }

    fn can_send(&mut self) {
        self.registers[LSR_OFFSET as usize] |= 0x20; // Can send
    }

    fn can_receive(&mut self) {
        self.registers[LSR_OFFSET as usize] |= 0x1; // Can receive
    }
}
