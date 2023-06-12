.syntax unified
.global main

.type main, %function
main:
  bl init
  mov r4, 0x7fff @stores current pitch
  mov r5, 0x7fff @stores highPitch
  mov r6, 0x8000 @stores lowPitch
  mov r8, 545 @number of instructions between switch
  mov r7, 2 @stores counter
  b loop

loop:
  cmp r7, r8
  add r7, #5
  IT hi
  bhi changePitch
  b playSound
 
playSound:
  mov r0, r4
  bl BSP_AUDIO_OUT_Play_Sample
  add r7, #5
  b loop

changePitch:
  cmp r4, r5
  ITE EQ
  moveq r4, r6
  movne r4, r5
  mov r7, 6
  b playSound

.size main, .-main