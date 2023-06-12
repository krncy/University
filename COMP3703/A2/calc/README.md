# calc

This binary is an implementation of a simple calculator, supporting computing arithmetic expressions over integers. The supported operators are `+` (addition), `*` (multiplication) and `-` (subtraction). Note that input containing negative numbers is not supported, though the result of the calculation can be a negative number. 

This calculator uses a modified version of Djikstra's shunting yard algorithm to parse arithmetic expressions. You can read about this algorithm [here](https://en.wikipedia.org/wiki/Shunting_yard_algorithm).
The shunting yard algorithm was originally developed to convert arithmetic expressions in an infix notation to expressions in a postfix notation, but is modified here to perform the calculation rather than for transforming expressions. 

Your task here is to exploit a buffer overflow vulnerability in the binary to capture the flag. Use the provided template python script (`solve_calc.py`) to automate your solution. An information leak (containing addresses) are given at the start of the program. Use this info leak to help you calculate relevant address(es) you may need as part of your exploitation.

_Hint:_ The binary uses two stacks to keep track of the states of the calculator; one holds a list of numbers (resulting from intermediate calculation steps) and the other holds the operators processed so far. You may want to reverse engineer this binary to learn the exact algorithm implemented. For the purpose of solving this assignment, it is not critical to evaluate whether the algorithm is implemented correctly. Rather you should try to find a scenario which would cause a buffer to grow out of bound; such an input may not be a typical arithmetic expressions so you need to think creatively. 


## Specific requirements

Your solution must use a stack-based exploitation technique and a ROP chain to obtain the flag. 

