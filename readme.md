# Operating Systems (CS330) 

## Repository Overview
This repository houses my solutions to the assignments completed during the Operating Systems Course (CS330) in the 5th semester at IIT Kanpur under the guidance of **Prof. Debadatta Mishra**. The solutions presented here reflect the hands-on experience gained in implementing various critical aspects of operating systems, including memory management, system calls, and fault handling.


## Assignments Overview

### Assignment 1: Dynamic Memory Management and Directory/File Size Calculation

- **Objective**: Implement API functions for dynamic memory allocation and deallocation, along with a utility to recursively calculate the size of any directory or file, including symbolic links.
- **Implementation Highlights**:
  - Developed a robust `memalloc()` and `memfree()` library, optimized to reduce memory fragmentation.
  - Implemented recursive directory size calculation, accounting for symbolic links.

### Assignment 2: Trace Buffer and Tracing Utilities Implementation in GemOS

- **Objective**: Extend GemOS to include trace buffer functionality (similar to `pipe()` functionality in UNIX), and implement `strace()` and `ftrace()` utilities
- **Implementation Highlights**:
  - Implemented the trace buffer functionality, supporting `create_pipe()`, `read()`, `write()`, and `close_pipe()` functionalities.
  - Developed `strace()` and `ftrace()` utilities to intercept and record system calls and function calls invoked by a process.
  - Integrated a fault handler to manage trace buffer overflows.
  - Validated `write` and `read` syscalls based on the read/write access permissions of code, data, heap, and stack segments.

### Assignment 3: Kernel-Level Memory Management with mmap, munmap, mprotect, and Copy-on-Write Fork

- **Objective**: Implement the `mmap()`, `munmap()`, and `mprotect()` system calls. Develop the `cfork()` syscall using a Copy-on-Write (CoW) fault handler to support lazy memory allocation.
- **Implementation Highlights**:
  - Extended the GemOS codebase to include the `mmap()`, `munmap()`, and `mprotect()` system calls.
  - Implemented a `cfork()` system call triggered by page faults supporting lazy allocation.

### Additional Notes

- **Object Files**: For Assignments 2 and 3, object files for various components were provided. The task was to modify and implement specific files: `tracer.c` for Assignment 2 and `v2p.c` for Assignment 3.
