import ctypes
import enum
import struct
decoder = ctypes.cdll.LoadLibrary('decode_wrapper.so')

"""
typedef struct
{
  int lineno;
  MSP430_Opcode_ID	id;
  unsigned		flags_1:8;	/* These flags are set to '1' by the insn.  */
  unsigned		flags_0:8;	/* These flags are set to '0' by the insn.  */
  unsigned		flags_set:8;	/* These flags are set appropriately by the insn.  */
  unsigned		zc:1;		/* If set, pretend the carry bit is zero.  */
  unsigned		repeat_reg:1;	/* If set, count is in REG[repeats].  */
  unsigned		ofs_430x:1;	/* If set, the offset in any operand is 430x (else use 430 compatibility mode).  */
  unsigned		repeats:5;	/* Contains COUNT-1, or register number.  */
  int			n_bytes;	/* Opcode size in BYTES.  */
  char *		syntax;
  MSP430_Size		size;		/* Operand size in BITS.  */
  MSP430_Condition	cond;
  /* By convention, these are [0]destination, [1]source.  */
  MSP430_Opcode_Operand	op[2];
} MSP430_Opcode_Decoded;

typedef struct
{
  MSP430_Operand_Type  type;
  int                  addend;
  MSP430_Register      reg : 8;
  MSP430_Register      reg2 : 8;
  unsigned char	       bit_number : 4;
  unsigned char	       condition : 3;
} MSP430_Opcode_Operand;
"""

@enum.unique
class OpcodeId(enum.IntEnum):
    Unknown = 0
    Mov = 1
    Add = 2
    Addc = 3
    Subc = 4
    Sub = 5
    Cmp = 6
    Dadd = 7
    Bit = 8
    Bic = 9
    Bis = 10
    Xor = 11
    And = 12
    Rrc = 13
    Swpb = 14
    Rra = 15
    Sxt = 16
    Push = 17
    Pop = 18
    Call = 19
    Reti = 20
    Jmp = 21
    Rru = 22

@enum.unique
class OperandType(enum.IntEnum):
    NoOperand = 0
    Immediate = 1
    Register = 2
    Indirect = 3
    Indirect_Postinc = 4

class Register(enum.IntEnum):
    PC = 0
    SP = 1
    SR = 2
    CG = 3
    R4 = 4
    R5 = 5
    R6 = 6
    R7 = 7
    R8 = 8
    R9 = 9
    R10 = 10
    R11 = 11
    R12 = 12
    R13 = 13
    R14 = 14
    R15 = 15
    NoRegister = 16

@enum.unique
class Size(enum.IntEnum):
    NoSize = 0
    Byte = 8
    Word = 16
    Addr = 20

@enum.unique
class Condition(enum.IntEnum):
    Nz = 0
    Z = 1
    Nc = 2
    C = 3
    N = 4
    Ge = 5
    L = 6
    Always = 7

class Opcode:
    def __init__(self, address, raw_instr, fields):
        assert len(fields) == 20

        self.address = address
        self.raw = raw_instr

        self.lineno = fields[0]
        self.opcode = OpcodeId(fields[1])
        self.flags_1 = fields[2]
        self.flags_0 = fields[3]
        self.flags_set = fields[4]
        self.zc = fields[5] & 0x1
        self.repeat_reg = (fields[5] & 0x2) >> 1
        self.ofs_430x = (fields[5] & 0x4) >> 2
        self.repeats = (fields[5] & 0xf8) >> 3
        self.n_bytes = fields[6]
        if fields[7]:
            self.syntax = ctypes.cast(fields[7], ctypes.c_char_p).value
        else:
            self.syntax = None
        self.size = Size(fields[8])
        self.cond = Condition(fields[9])
        self.dst = Operand(fields[10:15])
        self.src = Operand(fields[15:])

    def __repr__(self):
        return '<Opcode {} {} {}>'.format(self.opcode.name, self.dst, self.src)

class Operand:
    def __init__(self, field):
        assert len(field) == 5

        self.type_ = OperandType(field[0])
        self.addend = field[1]
        self.reg = Register(field[2])
        self.reg2 = Register(field[3])
        self.bit_number = field[4] & 0xf
        self.condition = (field[4] >> 4) & 0x7

    def __repr__(self):
        if self.type_ == OperandType.Immediate:
            return '<Operand Immediate {}>'.format(self.addend)
        elif self.type_ == OperandType.Register:
            return '<Operand Register {}>'.format(self.reg.name)
        else:
            return '<Operand {} {} {} {}>'.format(self.type_.name, self.reg.name, self.reg2.name, self.addend)

def msp430_decode_single(pc, buf):
    fmt_str = 'iiBBBBiPiiiiBBBxiiBBB'

    result = ctypes.c_buffer(struct.calcsize(fmt_str))
    read = decoder.msp430_decode_opcode_simple(pc, buf, len(buf), result)
    fields = struct.unpack(fmt_str, result.raw)

    return Opcode(pc, buf[:read], fields), read

def msp430_decoder(pc, buf):
    while True:
        op, read = msp430_decode_single(pc, buf)
        if read < 0 or read > len(buf):
            break

        pc += read
        buf = buf[read:]
        yield op
