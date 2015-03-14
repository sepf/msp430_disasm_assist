import binascii
import collections
import sys

import control_flow
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

def main():
    ih = intelhex.IntelHex(sys.argv[1])
    bytecode = bytes(ih.tobinarray())
    entry_point = ih[0xfffe] + (ih[0xffff] << 8)
    offset = entry_point - ih.minaddr()

    # Map from address to instruction
    instrs = collections.OrderedDict()
    for instr in decoder.msp430_decoder(ih.minaddr() + offset, bytecode[offset:]):
        instrs[instr.address] = instr

    labels = control_flow.generate_labels(entry_point, ih, instrs)
    blocks = control_flow.identify_control_flow(entry_point, ih, instrs, labels)
    addr_to_block = collections.OrderedDict((b.start_address, b) for b in sorted(blocks, key=lambda b: b.start_address))
    end_addr_to_block = collections.OrderedDict((b.terminal_instr.address, b) for b in sorted(blocks, key=lambda b: b.start_address))

    for instr in instrs.values():
        label = labels.get(instr.address)
        if label:
            print('{}:'.format(label))
        line = format_instr(instr, labels).ljust(60)

        # Add a column of semicolons to make it easier to document inline
        print(line, '; ', end='')
        block = addr_to_block.get(instr.address)
        if block:
            print('block.{} '.format(id(block),), end='')

        block = end_addr_to_block.get(instr.address)
        if block:
            print('end_block.{}'.format(id(block),), end='')
        print()

if __name__ == '__main__':
    main()
