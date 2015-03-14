import collections
import sys

import decoder
import intelhex
import msp430_labels

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
                instr.dst.type_ == decoder.OperandType.Register and
                instr.src.type_ == decoder.OperandType.Immediate):
            if instr.src.addend not in labels:
                labels[instr.src.addend] = make_jump_label()
        elif instr.opcode == decoder.OpcodeId.Call:
            if labels.get(instr.src.addend, 'l.').startswith('l.'):
                labels[instr.src.addend] = make_call_label()

    return labels

def instrs_iter(instrs, addr):
    while True:
        i = instrs.get(addr)
        if i is None:
            return

        yield i
        addr = i.address + i.n_bytes

class Block:
    def __init__(self, start_address):
        self.start_address = start_address
        self.terminal_instr = None
        self.next_blocks = []

    def __repr__(self):
        return '<Block {:06x} {}>'.format(self.start_address, self.terminal_instr)

def identify_control_flow(entry_point, raw_data, instrs, labels):
    blocks = []

    addr_to_block = {addr: Block(addr) for addr, label in labels.items() if label.startswith(('f.', 'isr.'))}
    addr_to_block[entry_point] = Block(entry_point)
    to_explore = list(addr_to_block.values())

    def enqueue_addr(block, addr):
        b = addr_to_block.get(addr)
        if not b:
            b = Block(addr)
            to_explore.append(b)
            addr_to_block[addr] = b
        block.next_blocks.append(b)

    while to_explore:
        block = to_explore.pop()
        prev_instr = None
        for instr in instrs_iter(instrs, block.start_address):
            done = False
            if instr.opcode == decoder.OpcodeId.Jmp:
                if instr.src.type_ == decoder.OperandType.Immediate:
                    enqueue_addr(block, instr.src.addend)
                if instr.cond != decoder.Condition.Always:
                    enqueue_addr(block, instr.address + instr.n_bytes)
                done = True
            elif (instr.opcode == decoder.OpcodeId.Mov and 
                    instr.dst.reg == decoder.Register.PC and
                    instr.dst.type_ == decoder.OperandType.Register):
                if instr.src.type_ == decoder.OperandType.Immediate:
                    enqueue_addr(block, instr.src.addend)
                done = True
            elif block.start_address != instr.address and labels.get(instr.address):
                block.terminal_instr = prev_instr
                blocks.append(block)
                break

            if done:
                block.terminal_instr = instr
                blocks.append(block)
                break

            prev_instr = instr
    blocks.sort(key=lambda b: b.start_address)
    return blocks

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
    blocks = identify_control_flow(entry_point, ih, instrs, labels)
    print(blocks)

if __name__ == '__main__':
    main()
