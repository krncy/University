# hexit

This binary converts user input into a hex strings. There is a buffer overflow vulnerability in the binary that you can exploit to print the flag. To help you solve this problem (with ASLR turned on), the libc base is printed in the beginning of its execution. Use this to craft the payload to exploit the binary. You must use the provided template python script (`solve_hexit.py`) to automate your solution. 

## Specific requirements

Your solution must use a stack-based exploitation technique to obtain the flag. 

