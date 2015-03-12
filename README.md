This is a basic tool for generating a more usable starting point for 
reverse-engineering MSP430 images.  It's pretty hacky at the moment,
but a lot nicer than the output of objdump, and easier to extend.

# Current Features versus objdump
- Label generation for interrupt service routines, targets of calls, and targets of jumps
- Resolves relative addresses into absolute addresses
- Resolves peripheral register names

# Building
This is not optimized for being painless :)
## libopcodes
To generate libbfd and libopcodes, download binutils source (tested 
with 2.25) and build with 
./configure --target=msp430 --shared --with-pic
## Actually building the tool
1. Copy the generate libbfd-2.25.so and libopcodes-2.25.so to your checkout.
2. Run make

# Running
python3 disasm.py `file.ihex`
