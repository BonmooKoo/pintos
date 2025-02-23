#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "devices/intq.h"

typedef int pid_t;
struct pipe {
    char *buffer;            // 링 버퍼 (예: 한 페이지)
    size_t capacity;         // 버퍼 용량
    size_t head;             // 읽기 위치
    size_t tail;             // 쓰기 위치
    struct lock lock;        // 동시 접근 보호
    struct condition not_empty; // 버퍼에 데이터가 있음
    struct condition not_full;  // 버퍼에 공간이 있음
    bool read_open;          // 읽기 끝이 열려 있는지 여부
    bool write_open;         // 쓰기 끝이 열려 있는지 여부
};


struct lock filesys_lock;

void syscall_init (void);
void check_address(const uint64_t *addr);
void halt(void);
void exit(int status);
pid_t exec(const char *cmd_line);
int wait(pid_t pid);
bool create(const char* file, unsigned int initial_size);
bool remove(const char* file);
int open(const char* file);
int filesize(int fd);
int read(int fd, void *buffer, unsigned int size);
int write(int fd, const void* buffer, unsigned int size);
void seek(int fd, unsigned int position);
unsigned int tell(int fd);
void close(int fd);



#endif /* userprog/syscall.h */
