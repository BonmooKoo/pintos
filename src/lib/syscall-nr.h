#ifndef __LIB_SYSCALL_NR_H
#define __LIB_SYSCALL_NR_H

/* System call numbers. */
enum 
  {
    /* Projects 2 and later. */
    SYS_HALT,                   /* 0Halt the operating system. */
    SYS_EXIT,                   /* 1Terminate this process. */
    SYS_EXEC,                   /* 2Start another process. */
    SYS_WAIT,                   /* 3Wait for a child process to die. */
    SYS_CREATE,                 /* 4Create a file. */
    SYS_REMOVE,                 /* 5Delete a file. */
    SYS_OPEN,                   /* 6Open a file. */
    SYS_FILESIZE,               /* 7Obtain a file's size. */
    SYS_READ,                   /* 8Read from a file. */
    SYS_WRITE,                  /* 9Write to a file. */
    SYS_SEEK,                   /* 10Change position in a file. */
    SYS_TELL,                   /* 11Report current position in a file. */
    SYS_CLOSE,                  /* 12Close a file. */

    /* Project 3 and optionally project 4. */
    SYS_MMAP,                   /* Map a file into memory. */
    SYS_MUNMAP,                 /* Remove a memory mapping. */

    /* Project 4 only. */
    SYS_CHDIR,                  /* Change the current directory. */
    SYS_MKDIR,                  /* Create a directory. */
    SYS_READDIR,                /* Reads a directory entry. */
    SYS_ISDIR,                  /* Tests if a fd represents a directory. */
    SYS_INUMBER                 /* Returns the inode number for a fd. */
  };

#endif /* lib/syscall-nr.h */
