# COMP3703 Semester 2 2023 -- Assignment 2

There are 7 (seven) problems in this assignment, listed below. For each assignment problem, more information is available in its corresponding folder in this repository. The relative weightage of each problem is as follows (with the total marks of 100): 

- Problem 1: leetspeak [10/100 marks]

- Problem 2: ihex8 [15/100 marks]

- Problem 3: hexit [15/100 marks]

- Problem 4: calc [25/100 marks]

- Problem 5: easyheap1 [5/100 marks]

- Problem 6: easyheap2 [5/100 marks]

- Problem 7: rps [25/100 marks]

Please check the submission guidelines below for the instructions on how to submit your assignment. Please also make sure you check [the Wattle page for this course](https://wattlecourses.anu.edu.au/course/view.php?id=39700) for other important information on the submission deadline and the assessment guidelines. 


## General requirements on the solutions

Your solution for each assignment problem must comply with the following general requirements:

- Your exploitation must be automated in a python script, using the provided template script, which can be found in the folder for each assignment problem. 

- Your exploitation script must work with ASLR enabled. This in particular means that you must not hardcode the libc base address and/or local buffer addresses as these can vary between different runs of the binary.  For problems that require precise libc base or buffer addresses to solve, the associated binaries will 'leak' some information on the relevant addresses when run, e.g., the libc base address. The provided template scripts contain code to capture this information if needed. 

- Your exploitation script must not use gdb (or other debuggers) to obtain the flag, libc base and/or buffer addresses. But you can use a debugger to help you in the process of finding an exploitation. 

- Your solution method for a problem must comply with the specific requirements for that problem, if any. Details of the specific requirements are in the README.md file for each problem. 

# Submission Guidelines

Submission will be primarily through Gitlab for this assignment. 

**PLEASE READ THE FOLLOWING CAREFULLY**


## To get started
- Fork this repository to your own namespace. 
    * **Make sure** that the 'visibility' of your fork is set to **private**.
    * **Make sure** that you select _your_ namespace. (this is only applicable to students who have greater than normal Gitlab access - others will only be able to select their own namespace.)
    * **DO NOT RENAME THE PROJECT - LEAVE THE NAME AND URL SLUG EXACTLY AS IS**
    * You may notice an additional member in your project - `comp3703-2023-s1-marker`. **Do not remove this member from your project**.
- Clone the repository to your virtual machine. You most likely will have to use HTTPS for this as SSH is unavailable to most connections.
- Get started!
  - Each question is contained within its own folder, and has its own README.md file. 
  - You can view rendered markdown using the Gitlab editor, or by opening the folder in VSCode.

## Working
- Make sure to commit and push to the Gitlab regularly to save your work
  * In the case that it is functional, the Gitlab CI pipeline is **only an indicator** of your progress, and does not correlate your mark. Remember that we still manually mark all submissions.
  * You may add and write your report source document (`.docx`, `.md`, whatever) to this repository if you wish
- Add your report PDF to this repository with the name "uXXXXXXX_report.pdf" where "uXXXXXXX" is your UID. **You will still have to submit your PDF report to turnitin**.

## Submission
- Make sure your **latest** report PDF has been uploaded to turnitin. **This is important, do not forget this.**
- Make sure your work is **committed and pushed** to this repository **before** the deadline (accounting for extensions/EAPs). 
  - As per the usual, a 100% late submission deduction applies.
- Once your work has been pushed to your Gitlab, you do not need to do anything further! We are able to fork your submissions for marking.
  - You can double check your submission status by going to your fork of the assignment and checking for your most recent commit.
  - Don't be afraid to ask questions about the process in the labs or on EdStem!

## Submission deadline

Please check [the Wattle page for this course](https://wattlecourses.anu.edu.au/course/view.php?id=39700) for the submission deadline for this assignment. It is your responsibility to ensure that your changes have been submitted to gitlab, what is present on gitlab at the time of the deadline will be considered your submission. The commit time of your repository will be used to determine whether or not you submitted on time. Please note that a late submission without a prior approval from the convener will receive 100% penalty. 


