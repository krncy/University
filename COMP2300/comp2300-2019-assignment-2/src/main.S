.syntax unified
.global main

.type main, %function

main:
  bl init
  b loadNotes

loadNotes:
  @works by storing the reference to the current note and the address after the last note and itterates through all the notes between them
  ldr r0, =notes
  ldr r1, =endNotes

  push {r0,r1}

  b mainLoop

mainLoop:
  @load the current and last address onto the stack
  pop {r0,r1}
  
  @if the address after the last note (r1) is equal to the address of the current note(r0) we have run out of notes, hence loop back to load notes play everything again
  cmp r0, r1
  beq loadNotes

  @get the frequency for the note at the current address
  ldr r2, [r0]
  @get the duration for the note at the current address (with an offset of 4)
  ldr r3, [r0, 4]
  @increase the address to the next address 
  add r0, 8

  @save the current address and last address onto the stack
  push {r0,r1}

  @move the fq and duration into the correct registers
  mov r0, r2
  mov r1, r3
  
  @only one of the ITE blocks should ever be run
  @if the hz = 0, then it is a sleep, so jump to a sleep function 
  @push r0, and r1 so they can be saved for the next comparrison
  push {r0}
  cmp r0, 0
  IT eq
  bleq sleep

  @r0 needs to be popped to ensure that if the previous ITE block runs, the next one wont. r1 doesnt need to be push/poped because if r1 is changed
  @it implies that the last ITE block ran and hence the next one does not need to be run so the value of r1 is now irrelevent 
  pop {r0}
  cmp r0, 0
  IT ne
  blne  playSoundForTime

  @play the next note
  b mainLoop
  
playSoundForTime:
  @save the link register so we can branch back to where we were - pop the lr onto the PC in the loop function
  push {lr}
 
  @initalise some registers
  mov r8, 0x7fff @stores current pitch
  mov r9, 0x7fff @stores highPitch
  mov r10, 0x8000 @stores lowPitch

  @r5 stores a constant which is the number of instructions before the note is finished being played 
  ldr r5, =#960
  mul r5, r1

  @r11 stores a constant which is the amount of instructions between changes in pitch
  ldr r11, = #425000 
  udiv r11, r11, r0 

  @r6 is a constant to store the number of instructions processed for the whole time the note is played
  mov r6, #11 

  @r12 is a counter to store the number of instructions processed between changes in pitch
  mov r12, #11

  b loop

loop:
  @update the counters
  add r6, #5
  add r12, #5

  @see if the time has run out yet, if so, pop the stack to the pc, the top address in the stack will always contains the lr value pushed at the start of the "playSoundForTime" label
  cmp r6, r5
  IT hi
  pophi {pc}

  @compare the pitch to see if it needs to be changed
  cmp r12, r11
  IT hi 
  blhi changePitch

  @update the instruction counters
  add r6, #6
  add r12, #6

  b playSound
 
changePitch:
  @find out which pitch is currently being played and change it to the other one
  cmp r8, r9
  ITE EQ
  moveq r8, r10
  movne r8, r9

  @reset the pitch counter (by subtracting to keep it in sync)
  sub r12, r11

  @update counters
  add r12, #8
  add r6, #8

  bx lr

playSound:
  @move the current pitch to r0 and play it, then update the counters and jump back to loop
  mov r0, r8
  bl BSP_AUDIO_OUT_Play_Sample
  add r12, #5 
  add r6, #5
  b loop 

sleep:
  @multiply a timer constant by the ms, r1 contains the number of instructions to hit
  ldr r0, =#67000
  mul r1, r1, r0

  @r0 is a counter to count the number of instructions
  mov r0, #6

  b count

count:
  @check if we've reached the number of instructions, and if so, jump back to the main loop
  cmp r0, r1
  IT hi
  bxhi lr

  @count the number of instructions and check the number of instructions again
  add r0, #5
  b count

@store the song in memory for a break, specify a hz of 0
@a note is stored in 2 words. The first word is the frequence of the note. The second word is the duration in (ms)
.data
  notes:
  .word 110, 250
  .word 0, 250
  .word 110, 250
  .word 0, 250
  .word 110, 250
  .word 0, 250
  .word 110, 250
  .word 0, 250
  .word 131, 250
  .word 0, 250
  .word 131, 250
  .word 0, 250
  .word 131, 250
  .word 0, 250
  .word 131, 250
  .word 147, 250
  .word 165, 250
  .word 0, 250
  .word 165, 250
  .word 0, 250
  .word 165, 250
  .word 0, 250
  .word 165, 250
  .word 0, 250
  .word 185, 125
  .word 0, 125
  .word 165, 125
  .word 0, 125
  .word 147, 125
  .word 0, 125
  .word 131, 125
  .word 0, 125
  .word 123, 125
  .word 0, 125
  .word 110, 125
  .word 0, 125
  .word 98, 250
  .word 110, 250
  endNotes:

.text

.size main, .-main