#include <stdlib.h>
#include "msp430-decode.h"

struct getbyte_arg {
    char *buf;
    int len;
    int consumed;
};

static int getbyte(void *v) {
    struct getbyte_arg *arg = (struct getbyte_arg *)v;
    if (arg->consumed >= arg->len) {
        return -1;
    }
    return arg->buf[arg->consumed++];
}

int msp430_decode_opcode_simple(unsigned long pc, char *buf, int buf_len, MSP430_Opcode_Decoded *instr) {
    // pc: first address in buf
    // buf: buffer of buf_len bytes of the source
    // instr: A place to write the decoded instruction information
    // Returns the number of bytes consumed from buf, or -1 if failed to decode
    
    struct getbyte_arg arg = { .buf = buf, .len = buf_len, .consumed = 0 };
    return msp430_decode_opcode(pc, instr, getbyte, &arg);
}
