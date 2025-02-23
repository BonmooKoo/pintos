#ifndef FILESYS_FILE_H
#define FILESYS_FILE_H

#include "filesys/off_t.h"
#include "threads/synch.h"
struct inode;
#define PIPE_BUFFER_SIZE 512

typedef struct pipe {
    char buffer[PIPE_BUFFER_SIZE]; // 링 버퍼
    int read_pos; // 읽기 위치
    int write_pos; // 쓰기 위치
    int size; // 현재 버퍼에 저장된 데이터 크기
    int reader_count;
    int writer_count;

    struct lock lock; // 동기화를 위한 락
    struct semaphore empty, full; // 파이프가 비거나 가득 찼을 때 동기화
};
/* An open file. */
typedef struct file
  {
    struct inode *inode;        /* File's inode. */
    off_t pos;                  /* Current position. */
    bool deny_write;            /* Has file_deny_write() been called? */
    int type;                   /* 0:regular file / 1:pipe*/
    struct pipe* pipe;           //save pipe
  };
/* Opening and closing files. */
struct file *file_open (struct inode *);
struct file *file_reopen (struct file *);
void file_close (struct file *);
struct inode *file_get_inode (struct file *);

/* Reading and writing. */
off_t file_read (struct file *, void *, off_t);
off_t file_read_at (struct file *, void *, off_t size, off_t start);
off_t file_write (struct file *, const void *, off_t);
off_t file_write_at (struct file *, const void *, off_t size, off_t start);

/* Preventing writes. */
void file_deny_write (struct file *);
void file_allow_write (struct file *);

/* File position. */
void file_seek (struct file *, off_t);
off_t file_tell (struct file *);
off_t file_length (struct file *);

#endif /* filesys/file.h */
