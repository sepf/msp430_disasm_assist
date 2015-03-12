import binascii
import collections
import sys

import decoder
import intelhex
import msp430_labels

ONE_OPERAND_INSTR = {
        decoder.OpcodeId.Sxt,
        decoder.OpcodeId.Push,
        decoder.OpcodeId.Pop,
        decoder.OpcodeId.Call,
        decoder.OpcodeId.Jmp,
        decoder.OpcodeId.Rru,
        decoder.OpcodeId.Rrc,
        decoder.OpcodeId.Swpb,
        decoder.OpcodeId.Rra,
        }
TWO_OPERAND_INSTR = {
        decoder.OpcodeId.Mov,
        decoder.OpcodeId.Add,
        decoder.OpcodeId.Addc,
        decoder.OpcodeId.Subc,
        decoder.OpcodeId.Sub,
        decoder.OpcodeId.Cmp,
        decoder.OpcodeId.Dadd,
        decoder.OpcodeId.Bit,
        decoder.OpcodeId.Bic,
        decoder.OpcodeId.Bis,
        decoder.OpcodeId.Xor,
        decoder.OpcodeId.And,
        }

def format_operand(operand, code_labels):
    if operand.type_ == decoder.OperandType.Immediate:
        label = code_labels.get(operand.addend)
        if label:
            return '#{}'.format(label)
        else:
            return '#{:#06x}'.format(operand.addend)
    elif operand.type_ == decoder.OperandType.Register:
        return operand.reg.name
    elif operand.type_ == decoder.OperandType.Indirect:
        # This is how libopcodes represents an absolute address (it translates symbolic ones to absolute behind the scenes)
        if operand.reg == decoder.Register.NoRegister and operand.reg2 == decoder.Register.PC:
            # Since we're dereferencing this, let's check if it's a peripheral
            # TODO: Make this more generic
            label = msp430_labels.msp430f21x2.get(operand.addend)
            if label:
                return '&{}'.format(label)
            else:
                return '&{:#06x}'.format(operand.addend)
        else:
            return '{:#06x}({})'.format(operand.addend, operand.reg.name)
    elif operand.type_ == decoder.OperandType.Indirect_Postinc:
        return '@{}+'.format(operand.reg.name)

def format_raw_instr(raw):
    assert len(raw) % 2 == 0
    words = ['    '] * 3
    for i in range(len(raw) // 2):
        words[i] = binascii.hexlify(raw[2*i:2*(i + 1)]).decode('latin1')

    return ' '.join(words)

def format_opcode(instr):
    opcode_parts = [instr.opcode.name]
    if instr.opcode == decoder.OpcodeId.Jmp and instr.cond != decoder.Condition.Always:
        opcode_parts.append(instr.cond.name)
    if instr.size == decoder.Size.Byte:
        opcode_parts.append('b')
    elif instr.size == decoder.Size.Addr:
        opcode_parts.append('a')
    return '.'.join(opcode_parts).lower().ljust(8)

def format_instr(instr, code_labels):
    parts = []
    raw_instr_str = format_raw_instr(instr.raw)
    opcode_str = format_opcode(instr)
    parts.append("{:x}: {}  {} ".format(instr.address, raw_instr_str, opcode_str))
    if instr.opcode in ONE_OPERAND_INSTR:
        parts.append(format_operand(instr.src, code_labels))
    elif instr.opcode in TWO_OPERAND_INSTR:
        parts.append("{}, {}".format(format_operand(instr.src, code_labels), format_operand(instr.dst, code_labels)))
    return ''.join(parts)

def generate_labels(entry_point, raw_data, instrs):
    """ Find all locations jumped to/called to and name them.
        
        This names call targets f.N and jump targets l.N (call target naming wins)
        The entry_point will be main
        Any interrupt service routine will be named isr.N
    """
    call_n = 0
    jump_n = 0

    def make_call_label():
        nonlocal call_n
        tmp = 'f.{}'.format(call_n)
        call_n += 1
        return tmp

    def make_jump_label():
        nonlocal jump_n
        tmp = 'l.{}'.format(jump_n)
        jump_n += 1
        return tmp

    labels = {}
    ivt_base = 0xffc0

    for i in range(32):
        iv_addr = ivt_base + 2 * i
        isr_addr = raw_data[iv_addr] + (raw_data[iv_addr + 1] << 8)
        # If we know what uses this interrupt, use a better name
        # TODO: Make this more generic
        label = msp430_labels.msp430f21x2_iv.get(iv_addr, 'isr.{}'.format(i))
        if isr_addr != 0xffff:
            if isr_addr in labels:
                labels[isr_addr] += ', {}'.format(label)
            else:
                labels[isr_addr] = label

    labels[entry_point] = 'main'

    for instr in instrs.values():
        if instr.opcode == decoder.OpcodeId.Jmp:
            if instr.src.addend not in labels:
                labels[instr.src.addend] = make_jump_label()
        elif (instr.opcode == decoder.OpcodeId.Mov and 
                instr.dst.reg == decoder.Register.PC and
                instr.dst.type_ == decoder.OperandType.Immediate):
            if instr.src.addend not in labels:
                labels[instr.src.addend] = make_jump_label()
        elif instr.opcode == decoder.OpcodeId.Call:
            if labels.get(instr.src.addend, 'l.').startswith('l.'):
                labels[instr.src.addend] = make_call_label()

    return labels

def main():
    ih = intelhex.IntelHex(sys.argv[1])
    bytecode = bytes(ih.tobinarray())
    entry_point = ih[0xfffe] + (ih[0xffff] << 8)
    offset = entry_point - ih.minaddr()

    # Map from address to instruction
    instrs = collections.OrderedDict()
    for instr in decoder.msp430_decoder(ih.minaddr() + offset, bytecode[offset:]):
        instrs[instr.address] = instr

    labels = generate_labels(entry_point, ih, instrs)

    for instr in instrs.values():
        label = labels.get(instr.address)
        if label:
            print('{}:'.format(label))
        line = format_instr(instr, labels).ljust(60)

        # Add a column of semicolons to make it easier to document inline
        print(line, '; ')

if __name__ == '__main__':
    main()
