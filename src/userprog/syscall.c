#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/palloc.h"
#include "filesys/off_t.h"
#include "filesys/inode.h"
#include "filesys/file.h"
#include "threads/malloc.h"
static void syscall_handler (struct intr_frame *);
struct file
{
	struct inode *inode;        /* File's inode. */
	off_t pos;                  /* Current position. */
	bool deny_write;            /* Has file_deny_write() been called? */
};
	void
syscall_init (void) 
{
	lock_init(&filesys_lock);
	intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}
//BM : system call handler function
void check_address(const uint64_t *addr){
	struct thread *cur = thread_current();
	if (addr == NULL || !(is_user_vaddr(addr)) || pagedir_get_page(cur->pagedir,addr)==NULL) {
		//seg fault
		exit(-1);
	}
}

void halt(void){
	shutdown_power_off();	
}

void exit(int status){
	struct thread *cur = thread_current();
	cur->exit_status = status;
	int i;
	if (cur->fd_table != NULL) {
		for (i = 3; i < 128; i++) { //0,1은 stdin / out
			if (cur->fd_table[i] != NULL) {
				file_close(cur->fd_table[i]);
				cur->fd_table[i] = NULL;
			}
		}
	}
	printf("%s: exit(%d)\n", thread_name(), status);
	thread_exit();
}

pid_t exec(const char* cmd_line){
	pid_t pid;
	int cmd_size = strlen(cmd_line)+1;
	if(cmd_size>PGSIZE){
		return -1; // limit 4KB
	}
	//lock_acquire (&filesys_lock);
	pid=process_execute(cmd_line);
	//lock_release(&filesys_lock);
	return pid;	
}
int wait(pid_t pid){
	int ret = process_wait(pid);
	return ret;
}
bool create(const char* file , unsigned initial_size){
	//printf("file pointer: %s\n", (void*)file);
	if(file==NULL){
		exit(-1);
	}
	//lock_acquire(&filesys_lock);
	bool ret = filesys_create(file,initial_size);
	//lock_release(&filesys_lock);
	return ret;	
}
bool remove(const char* file){
	if(file==NULL){
		exit(-1);
	}
	//lock_acquire(&filesys_lock);
	bool ret = filesys_remove(file);
	//lock_release(&filesys_lock);
	return ret;	
}
int open(const char* file){
	if(file==NULL){
		exit(-1);
	}
	lock_acquire(&filesys_lock);
	struct file* open_file = filesys_open(file);
	if(open_file==NULL){
		lock_release(&filesys_lock);
		return -1; // no file exist
	}
	//fd table
	struct thread* cur = thread_current();
	struct file** fdt = cur->fd_table;
	int fd;
	//lock_acquire(&filesys_lock);
	for(fd=3;fd<FDCOUNT_LIMIT;fd++){
		if(fdt[fd]==NULL){
			//file_deny_write(open_file);
			fdt[fd]=open_file;
			lock_release(&filesys_lock);
			return fd;
		}
	}
	// fd full
	file_close(open_file);
	lock_release(&filesys_lock);
	return -1;
}

int filesize(int fd){
	struct thread* cur = thread_current();
	if(fd<0||fd>=FDCOUNT_LIMIT||cur->fd_table[fd]==NULL)
		return -1;
	struct file* open_file = cur->fd_table[fd];
	return file_length(open_file);
}
int read(int fd, void* buffer, unsigned size){
	struct thread* cur = thread_current();
	check_address(buffer);
	if(fd<0||fd==1||fd>=FDCOUNT_LIMIT)
		exit(-1);
	lock_acquire(&filesys_lock);
	if(fd==0){ //stdio
		unsigned i;
		for(i=0;i<size;i++){
			((char*)buffer)[i] = input_getc();
			if(((char*)buffer)[i]=='\0')
				break;
		}
		lock_release(&filesys_lock);
		return i;	
	}
	else if (fd>2){
		struct file* open_file = cur->fd_table[fd];
		if(open_file==NULL){
			lock_release(&filesys_lock);
			exit(-1);//nofile exist
		}
		else{
			int read_size = file_read(open_file,buffer,size);
			lock_release(&filesys_lock);
			return read_size;
		}
	}
	lock_release(&filesys_lock);
	return -1;
}

int write(int fd,const void* buffer, unsigned size){
	//printf("write : fd : %d buffer :%s size: %d\n",fd,buffer,size);
	struct thread* cur = thread_current();
	struct file* open_file;
	int write_size;
	check_address(buffer);
        if(fd<=0 || fd>=FDCOUNT_LIMIT){
		exit(-1);
	}
	lock_acquire(&filesys_lock);
	if (fd == 1) { // 표준 출력 (콘솔)
		putbuf(buffer, size);
		write_size = size;
	}
	else if (fd>2){
		open_file=cur->fd_table[fd];
		if(open_file==NULL){
			lock_release(&filesys_lock);
			exit(-1);	
		}
		if (open_file->deny_write) {
			//file already read/ write by other thread
			file_deny_write(open_file);
		}
		write_size = file_write(open_file,buffer,size);
	}
	lock_release(&filesys_lock);
	return write_size;
}
void seek(int fd, unsigned position){
	struct thread* cur = thread_current();
	if(fd<0||fd>=FDCOUNT_LIMIT||cur->fd_table[fd]==NULL)
		return -1;//there is no file to close
	struct file* open_file=cur->fd_table[fd];
	//lock_acquire(&filesys_lock);
	file_seek(open_file,position);
	//lock_release(&filesys_lock);
}
unsigned tell(int fd){
	struct thread* cur = thread_current();
	if(fd<0||fd>=FDCOUNT_LIMIT||cur->fd_table[fd]==NULL)
		return -1;//there is no file to close
	struct file* open_file=cur->fd_table[fd];

	//lock_acquire(&filesys_lock);
	unsigned ret =file_tell(open_file);
	//lock_release(&filesys_lock);

	return ret;
}
void close (int fd){
	//fd table
	struct thread* cur = thread_current();
	if(fd<0||fd>=FDCOUNT_LIMIT||cur->fd_table[fd]==NULL)
		return -1;//there is no file to close
	struct file* open_file = cur->fd_table[fd];
	cur->fd_table[fd]=NULL;	
	//lock_acquire(&filesys_lock);
	file_close(open_file);
	//lock_release(&filesys_lock);
}
//BM : Signal function end

	static void
syscall_handler (struct intr_frame *f) 
{
	//BM : SYS call handler implement 
	//printf("syscall_handler : %d\n",*(int*)(f->esp));
	//hex_dump(f->esp,f->esp,100,1);
	int syscall_number = *(int*)(f->esp); // syscall number
	int status,fd;
	char* cmd_line,file;
	void* buffer;
	unsigned size,position;
	pid_t pid;
	switch(syscall_number){
		case SYS_HALT : 
			halt();
			break;
		case SYS_EXIT :
			check_address(f->esp + 4);
			exit((const char *)*(uint32_t *)(f->esp + 4));
			break;
		case SYS_EXEC :
			//cmd_line = *(char **)(f->esp + 4);
			check_address(f->esp + 4);
			f->eax = exec((const char *)*(uint32_t *)(f->esp + 4)); // return add
			break;
		case SYS_WAIT : 
			//pid = *(pid_t *)(f->esp + 4);
			check_address(f->esp + 4);
			f->eax = wait((const char *)*(uint32_t *)(f->esp + 4));
			break;
		case SYS_CREATE :
			//file = *(char**)(f->esp + 4 );
			//size = *(unsigned*)(f->esp + 8 );
			//printf("f->esp + 4 address: %p\n", (void *)(f->esp + 4));
			//printf("Value at f->esp + 4: %p\n", *(void **)(f->esp + 4));
			check_address(f->esp + 4);
			check_address(f->esp + 8);
			//f->eax = create(file,size);
			f->eax = create ( (const char *)*(uint32_t *)(f->esp + 4),  (const char *)*(uint32_t *)(f->esp + 8) );
			break;
		case SYS_REMOVE :
			//file = *(char**)(f->esp + 4 );
			check_address(f->esp + 4);
			f->eax = remove((const char *)*(uint32_t *)(f->esp + 4)); 
			break;
		case SYS_OPEN :
			//file = *(char**)(f->esp + 4 );
			check_address(f->esp + 4);
			f->eax = open((const char *)*(uint32_t *)(f->esp + 4));
			break;
		case SYS_FILESIZE :
			//fd = *(int*)(f->esp + 4 );
			check_address(f->esp + 4);
			f->eax = filesize((const char *)*(uint32_t *)(f->esp + 4));	
			break;
		case SYS_READ :
			//fd = *(int *)(f->esp + 4);
			//buffer = *(void **)(f->esp + 8);
			//size = *(unsigned *)(f->esp + 12);
			check_address(f->esp + 4);
			check_address(f->esp + 8);
			check_address(f->esp + 12);
			f->eax = read((const char *)*(uint32_t *)(f->esp + 4), (const char *)*(uint32_t *)(f->esp + 8), (const char *)*(uint32_t *)(f->esp + 12));
			break;
		case SYS_WRITE :
			//fd = *(int *)(f->esp + 4);
			//buffer = *(void **)(f->esp + 8);
			//size = *(unsigned *)(f->esp + 12);
			check_address(f->esp + 4);
			check_address(f->esp + 8);
			check_address(f->esp + 12);
			f->eax = write((const char *)*(uint32_t *)(f->esp + 4), (const char *)*(uint32_t *)(f->esp + 8), (const char *)*(uint32_t *)(f->esp + 12));
			break;
		case SYS_SEEK :
			//fd = *(int *)(f->esp + 4);
			//position = *(unsigned *)(f->esp + 8);
			check_address(f->esp + 4);
			check_address(f->esp + 8);
			seek((const char *)*(uint32_t *)(f->esp + 4), (const char *)*(uint32_t *)(f->esp + 8));
			break;
		case SYS_TELL :
			//fd = *(int *)(f->esp + 4);
			check_address(f->esp + 4);
			f->eax = tell((const char *)*(uint32_t *)(f->esp + 4));
			break;
		case SYS_CLOSE :
			//fd = *(int *)(f->esp + 4);
			check_address(f->esp + 4);
			close((const char *)*(uint32_t *)(f->esp + 4));
			break;
		case SYS_MMAP :
			break;
		case SYS_MUNMAP :
			break;
	}
	//printf("=============syscall end===========\n");
}
