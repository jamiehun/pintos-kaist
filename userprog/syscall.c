#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "threads/mmu.h"
#include "threads/init.h"
#include "filesys/filesys.h"
#include "user/syscall.h"
#include "threads/synch.h"
#include "filesys/file.h"
#include "userprog/process.h"


void syscall_entry (void);
void syscall_handler (struct intr_frame *);


/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);

	/* Initialize filesys_lock */
	lock_init(&filesys_lock);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.

	switch(f->R.rax)
	{
		
	// System Call 0 : Halt
	case SYS_HALT :
	{
		halt();
		break;
	}

	// System Call 1 : Exit
	case SYS_EXIT :
	{
		exit(f->R.rdi);
		break;
	}


	case SYS_FORK :
	{

		break;
	}


	case SYS_EXEC :
	{

		break;
	}


	case SYS_WAIT :
	{

		break;
	}

	// System Call 5 : Create
	case SYS_CREATE :
	{
		f->R.rax = create(f->R.rdi, f->R.rsi);
		break;
	}

    // System Call 6 : Remove
	case SYS_REMOVE :
	{
		f->R.rax = remove(f->R.rdi);
		break;
	}

	// System Call 7 : Open
	case SYS_OPEN :
	{
		f->R.rax = open(f->R.rdi);
		break;
	}

	// System Call 8 : Filesize
	case SYS_FILESIZE :
	{
		f->R.rax = filesize(f->R.rdi);
		break;
	}


	case SYS_READ :
	{
		f->R.rax = read(f->R.rdi,f->R.rsi,f->R.rdx);
		break;
	}

 
	case SYS_WRITE :
	{
		f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
		break;
	}


	case SYS_SEEK :
	{

		break;
	}

	case SYS_TELL :
	{

		break;
	}

	case SYS_CLOSE :
	{

		break;
	}


	}


	// printf ("system call!\n");
	// thread_exit ();
}

/* 주소 유효성 검사 - 포인터가 가리키는 주소가 사용자 영역 */
void 
check_address(void *addr)
{
	struct thread *t = thread_current();

	// 포인터가 가리키는 주소가 유저영역의 주소인지 확인
	// 잘못된 접근일 경우 프로세스 종료 

	/* Method 1: 
	 * Verify the validity of a user-provided pointer.
	 * The simplest way to handle user memory access.
	 * Use the functions in ‘userprog/pagedir.c’ and in ‘threads/vaddr.h’
     */

	/* User can pass invalid pointers through the systemcall
	 * 1) A pointer to kernel virtual memory address space (above PHYS_BASE)
	 * 2) A null pointer
	 * 3) A pointer to unmapped virtual memory
	 */
	if ((is_user_vaddr(addr) == false) || (addr == NULL) || (pml4_get_page (t->pml4, addr) == NULL))
		exit(-1);
}

/* System Call 0 : Halt */
void
halt (void){
	power_off();
}

/* System Call 1 : Create */
/* 한양대, pseudo code 적용 완료*/
void
exit (int status){
	struct thread *cur = thread_current();
	printf("%s: exit(%d)\n", cur->name, status); // 한양대 기준
	thread_exit(); 
}

/* System Call 5 : Create */
bool create(const char *file, unsigned initial_size){
	check_address(file);
	bool success = filesys_create(file, initial_size);
	return success;
}

/* System Call 6 : Remove */
bool remove (const char *file){
	check_address(file);
	bool success = filesys_remove(file);
	return success;
}

/* System Call 7 : Open */
int open(const char *file) {
	struct thread *cur = thread_current();
	cur->next_fd;

	check_address(file);

	if (lock_held_by_current_thread(&filesys_lock))
		return -1;
	
	lock_acquire(&filesys_lock);
	int i=0;
	do
	{
		i++;
		cur->next_fd += 1;

	} while (*(cur->fdt+i) != 0); // } while (cur->fdt[i] != 0);

	*(cur->fdt) = filesys_open(file);

	if (*(cur->fdt) == NULL)
		return -1;

	lock_release(&filesys_lock);

	return cur->next_fd;
}

/* System Call 8 : Filesize */
int filesize (int fd)
{
	int file_len;
	struct file * temp;

	temp = process_get_file(fd);

	if (temp == NULL)
		return -1;

	file_len = file_length(temp);

	return file_len;
}

/* System Call 10 : Read */
// int read (int fd, void* buffer, unsigned length)
// {
// 	int file_len;
// 	struct file * temp;
// 	off_t byte;
// 	check_address(buffer);
// 	// check_address(buffer+length-1);

// 	/* 파일에 동시접근이 일어날 수 있으므로 Lock 사용*/

// 	/* 파일 디스크립터를 이용하여파일객체검색*/

// 	/* 파일디스크립터가 0일경우 키보드의 입력을 버퍼에 저장 후 버퍼의 저장한 크기를 리턴(input_getc() 이용) */
// 	if (fd == 0){
// 		lock_acquire(&filesys_lock);
// 		int size;
// 		for (size=0; size<length; size++){
// 			*(uint8_t*)buffer=input_getc();
// 			buffer++;
// 		}
// 		lock_release(&filesys_lock);
// 		return size;
// 	}
// 	/* 음수이거나 63 초과 시*/
// 	else if(fd <= 1 || fd > 63){
// 		return -1;
// 	}
// 	/* 파일디스크립터가 0이아닐경우 파일의 데이터를 크기만큼 저장 후 읽은 바이트 수 를리턴*/
// 	else{
// 		lock_acquire(&filesys_lock);
// 		temp = process_get_file(fd);
// 		if (temp){
// 			byte=file_read(temp, buffer, length);
// 			if (byte==NULL)
// 				return -1;
// 			lock_release(&filesys_lock);
// 			return byte;
// 		}
// 		else{
// 			lock_release(&filesys_lock);
// 			return -1;
// 		}
// 	}
// }

/* System Call 10 : Read */
int read (int fd, void* buffer, unsigned length)
{
	int file_len;
	struct file * temp;
	off_t byte;
	check_address(buffer);
	if (fd == 1 || fd < 0 || fd > 63){
		return -1;
	}
	else if (fd == 0){
		lock_acquire(&filesys_lock);
		int size;
		if (length==0) return 0;
		for (size=0; size<length; size++){
			*(uint8_t*)buffer=input_getc();
			buffer++;
		}
		lock_release(&filesys_lock);
		return size;
	}
	else{
		lock_acquire(&filesys_lock);
		temp=process_get_file(fd);
		if (!temp){
			lock_release(&filesys_lock);
			return -1;
		}
		else{
			byte=file_read(temp,buffer,length);
			if (byte==0){
				lock_release(&filesys_lock);
				return 0;
			} 
			lock_release(&filesys_lock);
			return byte;
		}
	}
}

/* System Call 10 : Write */
// write 함수 초기 설정 ???
int write(int fd, const void *buffer, unsigned size)
{
	putbuf(buffer, size);
	return size;
}


