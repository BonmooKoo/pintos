#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
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
	printf("%s: exit(%d)\n", thread_name(), status);
	thread_exit();
}
pid_t exec(const char* cmd_line){
	check_address(cmd_line);
	int cmd_size = strlen(cmd_line)+1;
	if(cmd_size>PGSIZE){
		return -1; // limit 4KB
	}
	char *cmd_copy = palloc_get_page(PAL_ZERO);
	if (cmd_copy == NULL) {
		exit(-1);
	}
	strlcpy(cmd_copy, cmd_line, cmd_size);
	if (process_execute(cmd_copy) == -1) {//run process
		paloc_free_page(cmd_copy):
		return -1;
	}
	NOT_REACHED();
	return 0;	
}
int wait(pid_t pid){
	//TODO: process wait 수정하기
	return process_wait(pid);
}
bool create(const char* file , unsigned initial_size){
	check_address(file);
	if(file==NULL){
		return false;
	}
	return filesys_create(file, initial_size);	
}
bool remove(const char* file){
	check_address(file);
	if(file==NULL){
		return false;
	}
	return filesys_remove(file);
}
int open(const char* file){
	check_address(file);
	struct file* open_file = filesys_open(file);
	if(open_file==NULL)
		return -1; // no file exist
	//fd table
	struct thread* cur = thread_current();
	struct file** fdt = cur->fd_table;
	int fd;
	for(fd=2;fd<FDCOUNT_LIMIT;fd++){
		if(fdt[fd]==NULL){
			fdt[fd]=open_file;
			return fd;
		}
	}
	// fd full
	file_close(open_file0;
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
	check_address(buffer);
	struct thread* cur = thread_current();
	if(fd<0||fd>=FDCOUNT_LIMIT)
		return -1;
	struct file* open_file = cur->fd_table[fd];
	
	if(fd==0){ //stdio
		unsigned i;
		for(i=0;i<size;i++){
			((char*)buffer)[i] = input_getc();
		}
		return size;	
	}
	else{
		if(open_file==NULL){
			return -1;//nofile exist
		}
		else{
			lock_acquire(&filesys_lock);
			int read_size = file_read(open_file,buffer,size);
			lock_release(&filesys_lock);
			return read_size;
		}
	}
}
int write(int fd,const void* buffer, unsigned size){
	check_address(buffer);
	struct thread* cur = thread_current();
	struct file* open_file = cur->fd_table[fd];
	int write_size;
	lock_acquire(&filesys_loc);
	if (fd == 1) { // 표준 출력 (콘솔)
		putbuf(buffer, size);
        	return size;
    	}
	else{
		if(open_file==NULL){
			lock_release(&filesys_lock);
			return -1;
		}
		else{
			write_size = file_write(open_file,buffer,size);
		}
	}
	lock_release(&filesys_lock);
 	return write_size;
}
void seek(int fd, unsigned position){
	struct thread* cur = thread_current();
	if(fd<0||fd>=FDCOUNT_LIMIT||cur->fd_table[fd]==NULL)
		return -1;//there is no file to close
	}
	struct file* open_file=cur->fd_table[fd];
	file_seek(open_file,position);
}
unsigned tell(int fd){
	struct thread* cur = thread_current();
	if(fd<0||fd>=FDCOUNT_LIMIT||cur->fd_table[fd]==NULL)
		return -1;//there is no file to close
	}
	struct file* open_file=cur->fd_table[fd];
	return file_tell(open_file);
}
void close (int fd){
	 //fd table
        struct thread* cur = thread_current();
	if(fd<0||fd>=FDCOUNT_LIMIT||cur->fd_table[fd]==NULL)
		return -1;//there is no file to close
	}
	struct file* open_file = cur->fd_table[fd];
	file_close(open_file);
	cur->fd_table[fd]=NULL;	
        return 0;
}
//BM : Signal function end

static void
syscall_handler (struct intr_frame *f) 
{
  //BM : SYS call handler implement 
  int syscall_number = *(int*)(f->esp) // syscall number
  switch(syscall_number){
  	case SYS_HALT : 
		halt();
		break;
	case SYS_EXIT :
		int status = *(int *)(f->esp + 4);
		exit(status);
		break;
	case SYS_EXEC :
		char *cmd_line = *(char **)(f->esp + 4);
    		f->eax = exec(cmd_line); // return add
    		break;
	case SYS_WAIT : 
		pid_t pid = *(pid_t *)(f->esp + 4);
    		f->eax = wait(pid);
    		break;
	case SYS_CREATE :
		char* file = *(char**)(f->esp + 4 );
		unsigned size = *(unsigned*)(f->esp + 8);
		f->eax = create(file,size);
		break;
	case SYS_REMOVE :
		char* file = *(char**)(f->esp + 4 );
		f->eax = remove(file); 
		break;
	case SYS_OPEN :
		char* file = *(char**)(f->esp + 4 );
		f->eax = open(file);
		break;
	case SYS_FILESIZE :
		int fd = *(int*)(f->esp + 4 );
	 	f->eax = filesize(fd);	
		break;
	case SYS_READ :
		int fd = *(int *)(f->esp + 4);
		void *buffer = *(void **)(f->esp + 8);
		unsigned size = *(unsigned *)(f->esp + 12);
		f->eax = open(fd, buffer, size);
		break;
	case SYS_WRITE :
		int fd = *(int *)(f->esp + 4);
		void *buffer = *(void **)(f->esp + 8);
		unsigned size = *(unsigned *)(f->esp + 12);
		f->eax = write(fd, buffer, size);
		break;
	case SYS_SEEK :
		int fd = *(int *)(f->esp + 4);
		unsigned position = *(unsigned *)(f->esp + 8);
		f->eax = seek(fd, position);
		break;
	case SYS_TELL :
		int fd = *(int *)(f->esp + 4);
		f->eax = tell(fd);
		break;
	case SYS_CLOSE :
		int fd = *(int *)(f->esp + 4);
		f->eax = close(fd);
		break;
	case SYS_MMAP :
		break;
	case SYS_MUNMAP :
		break;
  }
}
