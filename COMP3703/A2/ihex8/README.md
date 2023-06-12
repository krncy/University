# ihex8

This binary converts an Intel HEX file to a binary file. Intel HEX is a file format to encode firmware binaries using ASCII texts. See the following article for details of this format: 

[https://en.wikipedia.org/wiki/Intel_HEX](https://en.wikipedia.org/wiki/Intel_HEX)

This format is essentially an ASCII file containing lines of texts, each line encodes a record type. For this assignment, the binary `ihex8` does not support the complete list of record types. It only supports the Data record type, which has the following format:

````
<header> <length> <offset> <code> <data> <checksum>
````

where each field is as follows:

- `<header>` is just a single character `:` (colon). 

- `<length>` is a 2-character hex string that encodes the length of the `<data>` field (see below).

- `<offset>` is a 4-character hex string that encodes the offset in the output file where the bytes `<data>` are  copied to. 

- `<code>`  is a 2-character hex string that encodes the record type. For the Data record type, this is the string `00`. 

- `<data>` is a hex string (2 or more characters) that encodes the actual bytes to be copied to the output file. The number of bytes this field encodes is specified in the `<length>` field above.

- `<checksum>` is a 2-character hex string that contains a checksum computed from `<length>`, `<offset>`, `<code>` and `<data>`. The checksum computation will be explained below. 

Here is an example of a string that encodes a valid Data record: 

````
:0B0010006164647265737320676170A7
````

The length of data in this case is encoded in the substring `0B`, which when interpreted as a hex number, is 11. The offset is `0010` (= 16), i.e., the data should be copied to offset 16 from the beginning of the file. The record type is `00` (Data record). The actual data is the sequence of bytes resulting from interpreting the hex string `6164647265737320676170` as a byte sequence. The checksum is the final byte `A7`.

To compute the checksum of a Data record, first discard the header `:`, and then convert the remaining string to a byte sequence. Then sum up all the individual bytes, compute the two's complement of the resulting integer, and take the (hex string of the ) least significant byte as the checksum. For example, for the above record type, the checksum is computed from the bytes 
`0B0010006164647265737320676170` (i.e., everything in between the first and the last bytes) as follows: 

- Sum up all the bytes (in hex notation): 

  `0B+00+10+00+61+64+64+72+65+73+73+20+67+61+70 = 0x0459`

- Compute two's complement of `0x0459`: we can do this by flipping the bits (using XOR) and add 1: 

  `(0x0459 XOR 0xFFFF) + 1 = 0x04A7`

- The hex string of the least significant byte `A7` is the checksum. 

The file `sample.hex` contains some more examples of valid Data records. 

The binary contains a buffer overflow vulnerability that can be exploited to print the flag. Use the provided template python script (`solve_ihex8.py`) to automate your solution. 

## Specific requirements

Your solution must use a stack-based exploitation technique to obtain the flag. 


