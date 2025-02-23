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

//pipe////////////////////////////////

//pipe end///////////////////////////

static void syscall_handler (struct intr_frame *);
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
	printf("%s: exit(%d)\n", thread_name(), status);
	thread_exit();
}

pid_t exec(const char* cmd_line){
	pid_t pid;
	struct thread* child=NULL;
	struct thread* t=NULL;
	struct list_elem* e;
	int cmd_size = strlen(cmd_line)+1;
	if(cmd_size>PGSIZE){
		return -1; // limit 4KB
	}
	pid=process_execute(cmd_line);
	//1. find child thread
	for (e = list_begin(&(thread_current()->child)); 
			e != list_end(&(thread_current()->child)); 
			e = list_next(e)) {	
		t = list_entry(e, struct thread, child_elem);
		if (pid == t->tid) {
			child = t;
			break;	
		}
	}
	//2.
	if(child!=NULL){
		if(child->load_flag==false){
			sema_down(&(child->load_lock));
			return -1;
		}
		else{
		/*	
			//1. copy parent FDT
			int i;
			int pipe_read_fd = -1;
			int pipe_write_fd = -1;
			for (i = 0; i < FDCOUNT_LIMIT; i++) {
				struct file *parent_f = thread_current()->fd_table[i];
				if (parent_f != NULL) {
					struct file* new_f = (struct file*)malloc(sizeof(struct file));
					*new_f = *parent_f;
					child->fd_table[i] = new_f;
				}
				else{
					child->fd_table[i] = NULL;
				}
			}
			//2. if there is pipe, redirect
			for (i = 0; i < FDCOUNT_LIMIT; i++) {
				struct file *f = child->fd_table[i];
				if (f && f->type == 1) {//type 1 : pipe
					if (pipe_read_fd == -1)
						// 첫 번째 PIPE FD를 읽기 FD로 가정
						pipe_read_fd = i; 
					else {
						// 두 번째 PIPE FD를 쓰기 FD로 가정
						pipe_write_fd = i; 
						// 파이프 쌍 찾음
						break; 
					}
				}
			}

			if (pipe_read_fd != -1 && pipe_write_fd != -1) {
				// 자식의 STDIN(0)을 PIPE_R로 리디렉션
				child->fd_table[0] = child->fd_table[pipe_read_fd];
				child->fd_table[pipe_read_fd] = NULL;

				// 쓰기 FD는 부모만 사용하므로 자식의 FD 테이블에서 제거
				free(child->fd_table[pipe_write_fd]);
				child->fd_table[pipe_write_fd] = NULL;
			}
		*/	
			sema_down(&(child->load_lock));
			return pid;
		}
	}
	else{
		sema_down(&(child->load_lock));
		return -1;	
	}
	//lock_release(&filesys_lock);
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

int allocate_fd(){
	int fd;
	struct thread* cur = thread_current();
	struct file** fdt = cur->fd_table;
	for(fd = 3;fd<FDCOUNT_LIMIT;fd++){
		if(fdt[fd]==NULL){
			return fd;
		}
	}	
	return -1;//full
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
	int fd = allocate_fd();
	if(fd==-1) {
		file_close(open_file);
		lock_release(&filesys_lock);
		return -1;
	}
	open_file->type= 0;//type 0 normal file
	thread_current()->fd_table[fd] = open_file;
	//lock_acquire(&filesys_lock);
	lock_release(&filesys_lock);
	return fd;	
}

int filesize(int fd){
	struct thread* cur = thread_current();
	if(fd<0||fd>=FDCOUNT_LIMIT||cur->fd_table[fd]==NULL)
		return -1;
	struct file* open_file = cur->fd_table[fd];
	return file_length(open_file);
}
int read_pipe(struct pipe *p, void *buffer, unsigned size) {
	if (p->writer_count == 0 && p->size == 0)
		return -1;

	unsigned i;
	for (i = 0; i < size; i++) {
		if (p->size == 0)
			break; // 버퍼가 비어 있으면 읽을 수 있는 만큼만 반환

		sema_down(&p->full);
		lock_acquire(&p->lock);

		((char *)buffer)[i] = p->buffer[p->read_pos]; // 데이터 읽기
		p->read_pos = (p->read_pos + 1) % PIPE_BUFFER_SIZE;
		p->size--;

		lock_release(&p->lock);
		sema_up(&p->empty);
	}

	return i; // 읽은 데이터 크기 반환
}
int read(int fd, void* buffer, unsigned size){
	struct thread* cur = thread_current();
	check_address(buffer);
	if(fd<0||fd==1||fd>=FDCOUNT_LIMIT)
		exit(-1);
	lock_acquire(&filesys_lock);
	/*//1. pipe
	if (fd == 0){
		struct file *pipe_file = cur->fd_table[0];
		if(pipe_file->type==1){
		lock_release(&filesys_lock);
		return read_pipe(pipe_file->pipe, buffer, size);
		}
	}
	*/

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
		//1. pipe
		/*if (open_file->type == 1) {//그럴일은 없겠지만....
			lock_release(&filesys_lock);
			return read_pipe(open_file->pipe, buffer, size);
		}*/
		int read_size = file_read(open_file,buffer,size);
		lock_release(&filesys_lock);
		return read_size;
	}
	lock_release(&filesys_lock);
	return -1;
}
int write_pipe(struct pipe *p, const void *buffer, unsigned size) {
	if (p->reader_count == 0) // 읽기 엔드가 모두 닫혔다면 에러 반환
		return -1;

	unsigned i;
	for (i = 0; i < size; i++) {
		sema_down(&p->empty); // 버퍼가 가득 차 있으면 대기
		lock_acquire(&p->lock);

		p->buffer[p->write_pos] = ((char *)buffer)[i]; // 데이터 쓰기
		p->write_pos = (p->write_pos + 1) % PIPE_BUFFER_SIZE;
		p->size++;

		lock_release(&p->lock);
		sema_up(&p->full); // 데이터가 추가되었으므로 읽기 가능
	}

	return size;
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
		/*//1. pipe
		if(open_file->type == 1){
			lock_release(&filesys_lock);
			return write_pipe(open_file->pipe,buffer,size);
		}*/
		if (open_file->deny_write) {
			//file already read/ write by other thread
			file_deny_write(open_file);
		}
		write_size = file_write(open_file,buffer,size);
	}
	else{//fd== 0 | 2
		write_size= -1;
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
	//1.pipe
	if(open_file->type == 1){
		free(open_file->pipe);
	}		
	//2. normal
	file_close(open_file);
	cur->fd_table[fd]=NULL;	
	//lock_acquire(&filesys_lock);
	//lock_release(&filesys_lock);
}
//proj2-2 : pipe
int pipe(int *fds) {
	struct thread* cur = thread_current();
	struct pipe *p = malloc(sizeof(struct pipe));

	// init pipe
	p->read_pos = 0;
	p->write_pos = 0;
	p->size = 0;
	p->reader_count = 1;
	p->writer_count = 1;
	lock_init(&p->lock);
	sema_init(&p->empty, PIPE_BUFFER_SIZE);
	sema_init(&p->full, 0);

	// alloc fd
	int fd0 = allocate_fd();
	int fd1 = allocate_fd();
	if (fd0 == -1 || fd1 == -1) {
		free(p);
		return -1;
	}	

	//set file type to pipe
	struct file *file_read = malloc(sizeof(struct file));
	struct file *file_write = malloc(sizeof(struct file));
	if (!file_read || !file_write) {
		free(p);
		return -1;
	}
	file_read->type = 1;//0 : normal file 1:pipe
	file_read->pipe = p;

	file_write->type = 1;//0 : normal file 1:pipe
	file_write->pipe = p;

	cur->fd_table[fd0] = file_read;
	cur->fd_table[fd1] = file_write;

	fds[0] = fd0; // 읽기 엔드
	fds[1] = fd1; // 쓰기 엔드
	return 0;
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
			//hex_dump(f->esp,f->esp,100,1);
			check_address(f->esp + 4);
			exit((const char *)*(uint32_t *)(f->esp + 4));
			break;
		case SYS_EXEC :
			//hex_dump(f->esp,f->esp,100,1);
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
		case SYS_PIPE:
			check_address(f->esp+4);
			//int pipe(int* fds)
			f->eax = pipe((const char *)*(uint32_t *)(f->esp + 4));
			break;
		case SYS_MMAP :
			break;
		case SYS_MUNMAP :
			break;
	}
	//printf("=============syscall end===========\n");
}
