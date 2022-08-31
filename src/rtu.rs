use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt, LittleEndian};
use enum_primitive::FromPrimitive;
use std::io::{self, Read, Write};
use std::time::Duration;

use crc::Crc;
use serial::{SerialPortSettings, Parity, StopBits, SerialPort, BaudRate};
use serial::unix::TTYPort;
use serial::core::SerialDevice;

use {binary, Client, Coil, Error, ExceptionCode, Function, Reason, Result};

const MODBUS_MAX_FRAME_SIZE: usize = 256;

/// Config structure for more control over the serial port settings
pub struct Config {
    pub device: String,
    pub parity: Parity,
    pub stop_bits: StopBits,
    pub timeout: Option<Duration>,
    pub baud_rate: BaudRate,
    pub modbus_uid: u8,
}

/// Context object which holds state for all modbus operations.
pub struct Transport {
    uid: u8,
    port: TTYPort,
}

impl Transport {
    pub fn new_with_cfg(cfg: Config) -> io::Result<Transport> {
        let mut port = serial::open(&cfg.device)?;
        if let Some(timeout) = cfg.timeout {
            SerialPort::set_timeout(&mut port, timeout)?;
        }
        let mut settings = port.read_settings()?;
        settings.set_baud_rate(cfg.baud_rate)?;
        settings.set_parity(cfg.parity);
        settings.set_stop_bits(cfg.stop_bits);
        port.write_settings(&settings)?;
        Ok(Transport {
            uid: cfg.modbus_uid,
            port
        })
    }

    fn read(&mut self, fun: &Function) -> Result<Vec<u8>> {
        let packed_size = |v: u16| v / 8 + if v % 8 > 0 { 1 } else { 0 };
        let (addr, count, expected_bytes) = match *fun {
            Function::ReadCoils(a, c) | Function::ReadDiscreteInputs(a, c) => {
                (a, c, packed_size(c) as usize)
            }
            Function::ReadHoldingRegisters(a, c) | Function::ReadInputRegisters(a, c) => {
                (a, c, 2 * c as usize)
            }
            _ => return Err(Error::InvalidFunction),
        };

        if count < 1 {
            return Err(Error::InvalidData(Reason::RecvBufferEmpty));
        }

        if count as usize > MODBUS_MAX_FRAME_SIZE {
            return Err(Error::InvalidData(Reason::UnexpectedReplySize));
        }

        let mut buff = Vec::new();
        buff.write_u8(self.uid)?;
        buff.write_u8(fun.code())?;
        buff.write_u16::<BigEndian>(addr)?;
        buff.write_u16::<BigEndian>(count)?;
        buff.write_u16::<LittleEndian>(Self::calculate_checksum(&buff[..]))?;

        self.port.write_all(&buff)?;
        let mut reply = vec![0; MODBUS_MAX_FRAME_SIZE];
        // Read address, function code and data count/exception code
        let mut header = &mut reply[0..3];
        self.port.read_exact(&mut header)?;
        Transport::validate_slave_address(self.uid, header)?;
        Transport::validate_response_code(&buff, header)?;

        let end = 3 + expected_bytes + 2;
        self.port.read_exact(&mut reply[3..end])?;
        let frame = &mut reply[0..end];
        Transport::validate_checksum(frame)?;
        Transport::get_reply_data(frame, expected_bytes)
    }

    fn calculate_checksum(packet: &[u8]) -> u16 {
        let modbus = Crc::<u16>::new(&crc::CRC_16_MODBUS);
        modbus.checksum(packet)
    }

    fn validate_response_code(req: &[u8], resp: &[u8]) -> Result<()> {
        if req[1] + 0x80 == resp[1] {
            match ExceptionCode::from_u8(resp[2]) {
                Some(code) => Err(Error::Exception(code)),
                None => Err(Error::InvalidResponse),
            }
        } else if req[1] == resp[1] {
            Ok(())
        } else {
            Err(Error::InvalidResponse)
        }
    }

    fn validate_slave_address(expected: u8, resp: &[u8]) -> Result<()> {
        if resp[0] == expected {
            Ok(())
        } else {
            Err(Error::InvalidResponse)
        }
    }

    fn validate_checksum(response: &[u8]) -> Result<()> {
        let mut checksum_buf = &response[response.len() - 2..];
        let found = checksum_buf.read_u16::<LittleEndian>()?;
        let calculated = Self::calculate_checksum(&response[0..response.len() - 2]);
        if calculated == found { Ok(()) } else { Err(Error::InvalidResponse) }
    }

    fn get_reply_data(reply: &[u8], expected_bytes: usize) -> Result<Vec<u8>> {
        if reply[2] as usize != expected_bytes
            || reply.len() != 3 + expected_bytes + 2
        {
            Err(Error::InvalidData(Reason::UnexpectedReplySize))
        } else {
            let mut d = Vec::new();
            d.extend_from_slice(&reply[3..reply.len() - 2]);
            Ok(d)
        }
    }

    fn write_single(&mut self, fun: &Function) -> Result<()> {
        let (addr, value) = match *fun {
            Function::WriteSingleCoil(a, v) | Function::WriteSingleRegister(a, v) => (a, v),
            _ => return Err(Error::InvalidFunction),
        };

        let mut buff = Vec::new();
        buff.write_u8(self.uid)?;
        buff.write_u8(fun.code())?;
        buff.write_u16::<BigEndian>(addr)?;
        buff.write_u16::<BigEndian>(value)?;
        self.write(&mut buff)
    }

    fn write_multiple(&mut self, fun: &Function) -> Result<()> {
        let (addr, quantity, values) = match *fun {
            Function::WriteMultipleCoils(a, q, v) | Function::WriteMultipleRegisters(a, q, v) => {
                (a, q, v)
            }
            _ => return Err(Error::InvalidFunction),
        };

        let mut buff = Vec::new();
        buff.write_u8(self.uid)?;
        buff.write_u8(fun.code())?;
        buff.write_u16::<BigEndian>(addr)?;
        buff.write_u16::<BigEndian>(quantity)?;
        buff.write_u8(values.len() as u8)?;
        for v in values {
            buff.write_u8(*v)?;
        }
        self.write(&mut buff)
    }

    fn write(&mut self, buff: &mut [u8]) -> Result<()> {
        if buff.is_empty() {
            return Err(Error::InvalidData(Reason::SendBufferEmpty));
        }

        if buff.len() + 2 > MODBUS_MAX_FRAME_SIZE {
            return Err(Error::InvalidData(Reason::SendBufferTooBig));
        }

        let mut buff = buff;
        buff.write_u16::<BigEndian>(Self::calculate_checksum(buff))?;

        self.port.write_all(buff)?;
        let reply = &mut [0; MODBUS_MAX_FRAME_SIZE]; // Slave address, function, byte count

        // Read address, function code and data count/exception code
        let header = &mut reply[0..3];
        self.port.read_exact(header).map_err(Error::Io)?;
        Transport::validate_slave_address(self.uid, header)?;
        Transport::validate_response_code(buff, header)?;

        // The response should be just an echo of the request
        self.port.read_exact(&mut reply[3..buff.len()])?;
        if &reply[0..buff.len()] != buff {
            Err(Error::InvalidResponse)
        } else {
            Ok(())
        }
    }
}

impl Client for Transport {
    /// Read `count` bits starting at address `addr`.
    fn read_coils(&mut self, addr: u16, count: u16) -> Result<Vec<Coil>> {
        let bytes = self.read(&Function::ReadCoils(addr, count))?;
        Ok(binary::unpack_bits(&bytes, count))
    }

    /// Read `count` input bits starting at address `addr`.
    fn read_discrete_inputs(&mut self, addr: u16, count: u16) -> Result<Vec<Coil>> {
        let bytes = self.read(&Function::ReadDiscreteInputs(addr, count))?;
        Ok(binary::unpack_bits(&bytes, count))
    }

    /// Read `count` 16bit registers starting at address `addr`.
    fn read_holding_registers(&mut self, addr: u16, count: u16) -> Result<Vec<u16>> {
        let bytes = self.read(&Function::ReadHoldingRegisters(addr, count))?;
        binary::pack_bytes(&bytes[..])
    }

    /// Read `count` 16bit input registers starting at address `addr`.
    fn read_input_registers(&mut self, addr: u16, count: u16) -> Result<Vec<u16>> {
        let bytes = self.read(&Function::ReadInputRegisters(addr, count))?;
        binary::pack_bytes(&bytes[..])
    }

    /// Write a single coil (bit) to address `addr`.
    fn write_single_coil(&mut self, addr: u16, value: Coil) -> Result<()> {
        self.write_single(&Function::WriteSingleCoil(addr, value.code()))
    }

    /// Write a single 16bit register to address `addr`.
    fn write_single_register(&mut self, addr: u16, value: u16) -> Result<()> {
        self.write_single(&Function::WriteSingleRegister(addr, value))
    }

    /// Write a multiple coils (bits) starting at address `addr`.
    fn write_multiple_coils(&mut self, addr: u16, values: &[Coil]) -> Result<()> {
        let bytes = binary::pack_bits(values);
        self.write_multiple(&Function::WriteMultipleCoils(
            addr,
            values.len() as u16,
            &bytes,
        ))
    }

    /// Write a multiple 16bit registers starting at address `addr`.
    fn write_multiple_registers(&mut self, addr: u16, values: &[u16]) -> Result<()> {
        let bytes = binary::unpack_bytes(values);
        self.write_multiple(&Function::WriteMultipleRegisters(
            addr,
            values.len() as u16,
            &bytes,
        ))
    }

    /// Set the unit identifier.
    fn set_uid(&mut self, uid: u8) {
        self.uid = uid;
    }
}
