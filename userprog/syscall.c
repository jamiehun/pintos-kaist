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


	case SYS_OPEN :
	{

		break;
	}


	case SYS_FILESIZE :
	{

		break;
	}


	case SYS_READ :
	{

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


/* System Call 10 : Write */
// write 함수 초기 설정 ???
int write(int fd, const void *buffer, unsigned size)
{
	putbuf(buffer, size);
	return size;
}


