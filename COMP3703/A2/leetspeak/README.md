# leetspeak

This binary translates English texts to [`leetspeak`](https://en.wikipedia.org/wiki/Leet) but it has a buffer overflow vulnerability. Exploit that vulnerability to print the flag. Use the provided template python script (`solve_leetspeak.py`) to automate your solution. 

## Specific requirements

Your solution must use a stack-based exploitation technique to inject executable code in the stack frame of a vulnerable function, and execute it to print the flag. You must use the function `create_code()` in `solve_leetspeak.py` to create the code to inject. 