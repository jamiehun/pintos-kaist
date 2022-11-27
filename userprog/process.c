#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/mmu.h"
#include "threads/vaddr.h"
#include "intrinsic.h"
#ifdef VM
#include "vm/vm.h"
#endif

static void process_cleanup (void);
static bool load (const char *file_name, struct intr_frame *if_);
static void initd (void *f_name);
static void __do_fork (void *);

/* General process initializer for initd and other process. */
static void
process_init (void) {
	struct thread *current = thread_current ();
}

/* FILE_NAME으로부터 load된 "initd"라는 첫번째 userland program을 시작한다. 
   thread_creat()해서 thread생성 후 tid 반환 */
/* 프로세스(쓰레드)를 생성하는 함수를 호출하고 tid를 반환한다 */
/* Starts the first userland program, called "initd", loaded from FILE_NAME.
 * The new thread may be scheduled (and may even exit)
 * before process_create_initd() returns. Returns the initd's
 * thread id, or TID_ERROR if the thread cannot be created.
 * Notice that THIS SHOULD BE CALLED ONCE. */
tid_t
process_create_initd (const char *file_name) {
	char *fn_copy;
	tid_t tid;
	//(추측)file_name 문자열을 파싱(첫번째 토큰)
	/* Make a copy of FILE_NAME.
	 * Otherwise there's a race between the caller and load(). */
	fn_copy = palloc_get_page (0);
	if (fn_copy == NULL)
		return TID_ERROR;
	//(추측)커맨드라인에서 프로세스이름 확인 
	strlcpy (fn_copy, file_name, PGSIZE);
	
	char *token, *save_ptr;
	strtok_r (file_name, " ", &save_ptr);

	/* Create a new thread to execute FILE_NAME. */
	// file_name: 스레드이름(문자열), PRI_DEFAULT: 스레드우선순위(31)
	// initd: 생성된 스레드가 실행할 함수를 가리키는 포인터, fn_copy: start_process 함수를 수행할 때 사용하는 인자값
	// initd : 1st argument(rdi) , fn_copy : 2nd argument(rsi)
	tid = thread_create (file_name, PRI_DEFAULT, initd, fn_copy);
	if (tid == TID_ERROR)
		palloc_free_page (fn_copy);
	return tid;
}

/* A thread function that launches first user process. */
static void
initd (void *f_name) {
#ifdef VM
	supplemental_page_table_init (&thread_current ()->spt);
#endif
	process_init ();
	if (process_exec (f_name) < 0)
		PANIC("Fail to launch initd\n");
	NOT_REACHED ();
}

/* Clones the current process as `name`. Returns the new process's thread id, or
 * TID_ERROR if the thread cannot be created. */
/* 인터럽트 프레임 : 인터럽트가 호출됐을 때 이전에 레지스터에 작업하던 context 정보를 스택에 담는 구조체(Woony)*/
// (woony)
// 즉, 유저 프로그램 실행 정보는 syscall_handler로 전달되는 intr_frame에 저장된다. 이를 __do_fork에 넘겨주는 방식. 
// 따라서 우리가 구현해야 하는 시스템 콜 핸들러의 fork 함수에는 thread_name과 tf를 인자로 받아야 하며, 
// 이때 전달되는 tf는 시스템 콜 핸들러로 넘어온 f에 정보가 들어있다.
tid_t
process_fork (const char *name, struct intr_frame *if_ UNUSED) {
	/* Clone current thread to new thread.*/
	struct thread *parent = thread_current();
	tid_t child_tid;
	/* parent_if에 유저스택 정보 담기*/
	memcpy(&parent->parent_if,if_,sizeof(struct intr_frame));//if_는 유저스택, 이 정보를(userland context)를 Parent_if에 넘겨준다
	/* 자식 스레드를 생성 */
	child_tid=thread_create (name,	// function함수를 실행하는 스레드 생성
			PRI_DEFAULT, __do_fork, thread_current ()); //부모스레드는 현재 실행중인 유저 스레드
	if (child_tid==TID_ERROR)
		return TID_ERROR;
	/* Project 2 fork()*/
	/* get_child()를 통해 해당 p sema_fork 값이 1이 될 때까지(=자식 스레드 load가 완료될 때까지)를 기다렸다가 끝나면 pid를 반환 */
	struct thread *child = get_child_process(child_tid);
	sema_down(&child->sema_fork);
	// printf("========child_tid======%d\n", child_tid);
    // if (child->process_exit_status == -1)
    // {
    //     return TID_ERROR;
    // }
	return child_tid;
}

#ifndef VM
/* Duplicate the parent's address space by passing this function to the
 * pml4_for_each. This is only for the project 2. */
static bool
duplicate_pte (uint64_t *pte, void *va, void *aux) {
	struct thread *current = thread_current ();     // ??? current가 자식 스레드
	struct thread *parent = (struct thread *) aux;  // 
	void *parent_page;
	void *newpage;
	bool writable;

	/* 1. TODO: If the parent_page is kernel page, then return immediately. */
	if (is_kern_pte(pte)) return true; // !!! pte가 parent page 인가?
	// if (is_kernel_vaddr(va)) return false; // ??? pte가 parent page 인가?
	
	/* 2. Resolve VA from the parent's page map level 4. */
	parent_page = pml4_get_page (parent->pml4, va); // parent->pml4에서 
	if (parent_page == NULL){
		return false;
	}
	/* 3. TODO: Allocate new PAL_USER page for the child and set result to
	 *    TODO: NEWPAGE. */
	newpage = palloc_get_page(PAL_USER | PAL_ZERO);
	if(newpage == NULL) {
		return false;
	}

	/* 4. TODO: Duplicate parent's page to the new page and
	 *    TODO: check whether parent's page is writable or not (set WRITABLE
	 *    TODO: according to the result). */
	memcpy(newpage, parent_page, PGSIZE);
	// memcpy(newpage, parent_page, PGSIZE);
	writable=is_writable(pte);


	/* pml4_set_page로 가상메모리와 물리메모리를 맵핑함 (writable에 대한 정보를 가지고서) */
	/* 5. Add new page to child's page table at address VA with WRITABLE
	 *    permission. */
	if (!pml4_set_page (current->pml4, va, newpage, writable)) {
		/* 6. TODO: if fail to insert page, do error handling. */
		return false;
	}
	return true;
}
#endif

/* 부모 프로세스의 실행 context를 자식 프로세스로 복사하는 함수(by Woony) */
/* A thread function that copies parent's execution context.
 * Hint) parent->tf does not hold the userland context of the process.
 *       That is, you are required to pass second argument of process_fork to
 *       this function. */
/* 인터럽트 프레임 : 인터럽트가 호출됐을 때 이전에 레지스터에 작업하던 context 정보를 스택에 담는 구조체(Woony)*/
static void
__do_fork (void *aux) {	//process_fork함수에서 thread_create()을 호출하면서 aux는 thread_current()를 들고옴
	struct intr_frame if_; // ??? 자식 인터럽트 프레임?
	struct thread *parent = (struct thread *) aux;
	struct thread *current = thread_current (); //???자식스레드로 추측됨
	// printf("========child_tid11======%d\n", current->tf.R.rax);


	/* TODO: somehow pass the parent_if. (i.e. process_fork()'s if_) */
	/* parent->tf (부모 프로세스 구조체 내 인터럽트 프레임 멤버)는 프로세스의 userland context 정보를 들고 있지 않다.
	즉, 당신은 process_fork()의 두번째 인자를 이 함수에 넘겨줘야만 한다.*/
	struct intr_frame *parent_if; //부모 인터럽트 프레임
	parent_if = &parent->parent_if; // 넘어온 부모 인터럽트(userland context가 담긴)를 프레임을 다시 저장 
	// memcpy (parent_if, &parent->parent_if, sizeof (struct intr_frame)); // ??? 자식에게 넘겨주는것
	// printf("========child_tid22======%d\n", current->tf.R.rax);

	bool succ = true;

	/* 1. Read the cpu context to local stack. */
	memcpy (&if_, parent_if, sizeof (struct intr_frame)); // ??? 자식에게 넘겨주는것

	/* 2. Duplicate PT */
	current->pml4 = pml4_create();
	if (current->pml4 == NULL)
		goto error;

	// printf("========child_tid33======%d\n", current->tf.R.rax);
	process_activate (current);
	// printf("========child_tid44*****%d\n", current->tf.R.rax);

#ifdef VM
	// printf("========child_tid44*****%d\n", current->tf.R.rax);
	supplemental_page_table_init (&current->spt);
	if (!supplemental_page_table_copy (&current->spt, &parent->spt))
		goto error;
	// printf("========child_tid44======%d\n", current->tf.R.rax);
	
#else
	// printf("========child_tid44*****%d\n", current->tf.R.rax);
	if (!pml4_for_each (parent->pml4, duplicate_pte, parent)){
		// printf("^^^^^^!pml4_for_each:(%d)\n", !pml4_for_each (parent->pml4, duplicate_pte, parent));
		goto error;
	}
	// printf("========child_tid77*****%d\n", current->tf.R.rax);
#endif

	/* TODO: Your code goes here.
	 * TODO: Hint) To duplicate the file object, use `file_duplicate`
	 * TODO:       in include/filesys/file.h. Note that parent should not return
	 * TODO:       from the fork() until this function successfully duplicates
	 * TODO:       the resources of parent.*/
	// printf("========child_tid55======%d\n", current->tf.R.rax);

	if (parent->fd_idx==(1<<9))
		goto error;
	// for (int fd=0; fd<64;fd++){
	for (int fd=0; fd<(1<<9);fd++){
		if (fd<=1){
			current->fdt[fd]=parent->fdt[fd];
		}
		else{
			if(parent->fdt[fd]!=NULL)
				current->fdt[fd]=file_duplicate(parent->fdt[fd]);
		}
	}
	current->fd_idx=parent->fd_idx;
	// printf("========child_tid66======%d\n", current->tf.R.rax);


	current->fd_idx=parent->fd_idx;
	// printf("========child_tid2======%d\n", current->tf.R.rax);

	sema_up(&current->sema_fork);
	/* 자식 프로세스 0으로 반환 */
	if_.R.rax = 0;
	// printf("========child_tid3======%d\n", current->tf.R.rax);

	// printf(">>>>>>>parent : %d\n",parent->status);
	// printf(">>>>>>>child : %d\n",current->status);
	process_init ();



	/* Finally, switch to the newly created process. */
	if (succ)
		do_iret (&if_);


error:
	sema_up(&current->sema_fork);
	// thread_exit ();
	exit(TID_ERROR); // GitBook 참고
}

/* (한양대 : start_process, CSAPP p.721) 프로그램을 메모리에 적재(load) 후 프로그램 시작*/
/* Switch the current execution context to the f_name.
 * Returns -1 on fail. */
int
process_exec (void *f_name) {	// f_name = 'args-single onearg'
	char *file_name = f_name;
	bool success;

	// 성훈 sema down

	/* 인자들을 띄어쓰기 기준으로 토큰화 및 토큰의 개수계산 (strtok_r() 함수이용) */
	// strtok_r() 함수를 이용해 인자들을 토큰화하여 토큰의 개수를 계산한다.
	//??인터럽트 프레임 초기화
	// Setup virtual address of the program: code, data, stack (user stack) (추측)
	/* We cannot use the intr_frame in the thread structure.
	 * This is because when current thread rescheduled,
	 * it stores the execution information to the member. */
	/* Context change가 일어날 때 thread_launch()와 do_iret() 함수에서 아래와 같은 과정이 이루어지며, 이 과정에서 interrupt frame이 활용됩니다.
	 * (1) 현재 cpu의 register 값들을 current thread(T1)의 intr_frame (tf)로 옮긴다.
	 * (2) 새롭게 실행할 thread(T2)의 intr_frame에 있는 값을 cpu register로 옮긴다.
	 * (3) iretq instruction을 활용해 T2에서 실행하던 코드를 마저 실행한다.
	 * 정리하자면, intr_frame에 들어가야 할 내용은 cpu register에 있는 값입니다. 따라서 kernel memory에 별도로 저장되어 있는 값이 아닙니다. */
	struct intr_frame _if;
	_if.ds = _if.es = _if.ss = SEL_UDSEG;
	_if.cs = SEL_UCSEG;
	_if.eflags = FLAG_IF | FLAG_MBS;

	/* We first kill the current context */
	process_cleanup ();
	
	//Argument parsing (커맨드 라인 Parsing 하여 인자 확인)

	/* And then load the binary */
	// file_name : 프로그램(실행파일) 이름

	success = load (file_name, &_if);
	// sema_down(&thread_current()->sema_load);
	// 영우 sema down


	// 의균 sema up

	/* If load failed, quit. */
	palloc_free_page (file_name);
	if (!success)	//메모리 적재 실패시 -1 반환
		return -1;

	// hex_dump(_if.rsp,_if.rsp,USER_STACK-_if.rsp,true);
	
	/* Start switched process. */
	// 성공하면 유저 프로그램을 실행한다
	// do interrupt return

	// 성훈 sema up

	do_iret (&_if);
	
	// asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&_if) : "memory");
	NOT_REACHED ();
}

/* 자식프로세스(child_tid)가 종료될 때 가지 대기 하다가 정상종료시 exit_status 반환,
   비정상 종료(exception으로 인해 종료)시 -1반환.
   1) TID가 잘못되었거나 
   2) TID가 호출 프로세스의 자식이 아니거나 
   3) 지정된 TID에 대해 process_wait()이 이미 성공적으로 호출된 경우 
   대기하지 않고 -1을 즉시 반환.*/
/* Waits for thread TID to die and returns its exit status.  If
 * it was terminated by the kernel (i.e. killed due to an
 * exception), returns -1.  If TID is invalid or if it was not a
 * child of the calling process, or if process_wait() has already
 * been successfully called for the given TID, returns -1
 * immediately, without waiting.
 * 
 * This function will be implemented in problem 2-2.  For now, it
 * does nothing. */
int
process_wait (tid_t child_tid UNUSED) {
	/* XXX: Hint) The pintos exit if process_wait (initd), we recommend you
	 * XXX:       to add infinite loop here before
	 * XXX:       implementing the process_wait. */
	// thread_set_priority(3); 
	// return -1;
	/*자식프로세스가 모두 종료 될 때 까지 대기(sleep state)
	자식프로세스가 올바르게 종료됐는지 확인*/

	// struct thread *parent = thread_current();
	struct thread *child = get_child_process(child_tid);
	/* 1) TID가 잘못되었거나 2) TID가 호출 프로세스의 자식이 아니거나*/ 
	if (child==NULL){
		return -1;
	}
	/* 3) 지정된 TID에 대해 process_wait()이 이미 성공적으로 호출된 경우 */
	if (child->is_waited_flag==true) return -1;
	else child->is_waited_flag=true;

	/* 자식프로세스가 종료될 때 까지 부모프로세스 대기(세마포어이용) */
	sema_down(&child->sema_wait);
	int exit_status = child->process_exit_status;

	/* 자식프로세스 디스크립터 삭제*/
	remove_child_process(child);
	// sema_up(&child->sema_free); // wake-up child in process_exit - proceed with thread_exit
	return exit_status;
}

/* Exit the process. This function is called by thread_exit (). */
void
process_exit (void) {
	struct thread *cur = thread_current ();
	// printf("%s: exit(%d)\n", cur->name, status); 
	
	/* 1 : 정상종료? */
	// cur->process_exit_status=cur->tid;

	/* TODO: Your code goes here.
	 * TODO: Implement process termination message (see
	 * TODO: project2/process_termination.html).
	 * TODO: We recommend you to implement process resource cleanup here. */
	// list_entry(cur.)
	sema_up(&cur->sema_wait); //fault!!
	// Postpone child termination until parents receives its exit status with 'wait'
	// sema_down(&cur->sema_free);

	file_close (cur->running_file);
	process_cleanup ();
}

/* Free the current process's resources. */
static void
process_cleanup (void) {
	struct thread *curr = thread_current ();

#ifdef VM
	supplemental_page_table_kill (&curr->spt);
#endif

	uint64_t *pml4;
	/* Destroy the current process's page directory and switch back
	 * to the kernel-only page directory. */
	pml4 = curr->pml4;
	if (pml4 != NULL) {
		/* Correct ordering here is crucial.  We must set
		 * cur->pagedir to NULL before switching page directories,
		 * so that a timer interrupt can't switch back to the
		 * process page directory.  We must activate the base page
		 * directory before destroying the process's page
		 * directory, or our active page directory will be one
		 * that's been freed (and cleared). */
		curr->pml4 = NULL;
		pml4_activate (NULL);
		pml4_destroy (pml4);
	}
}

/* Sets up the CPU for running user code in the nest thread.
 * This function is called on every context switch. */
void
process_activate (struct thread *next) {
	/* Activate thread's page tables. */
	pml4_activate (next->pml4);

	/* Set thread's kernel stack for use in processing interrupts. */
	tss_update (next);
}

/* We load ELF binaries.  The following definitions are taken
 * from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
#define EI_NIDENT 16

#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
 * This appears at the very beginning of an ELF binary. */
struct ELF64_hdr {
	unsigned char e_ident[EI_NIDENT];
	uint16_t e_type;
	uint16_t e_machine;
	uint32_t e_version;
	uint64_t e_entry;
	uint64_t e_phoff;
	uint64_t e_shoff;
	uint32_t e_flags;
	uint16_t e_ehsize;
	uint16_t e_phentsize;
	uint16_t e_phnum;
	uint16_t e_shentsize;
	uint16_t e_shnum;
	uint16_t e_shstrndx;
};

struct ELF64_PHDR {
	uint32_t p_type;
	uint32_t p_flags;
	uint64_t p_offset;
	uint64_t p_vaddr;
	uint64_t p_paddr;
	uint64_t p_filesz;
	uint64_t p_memsz;
	uint64_t p_align;
};

/* Abbreviations */
#define ELF ELF64_hdr
#define Phdr ELF64_PHDR

static bool setup_stack (struct intr_frame *if_);
static bool validate_segment (const struct Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes,
		bool writable);

/* 메모리를 할당받고 사용자 프로그램을 메모리에 적재*/
/* Loads an ELF executable from FILE_NAME into the current thread.
 * Stores the executable's entry point into *RIP(프로그램 카운터:실행할 다음 인스트럭션의 메모리 주소를 가리키는 포인터)
 * and its initial stack pointer into *RSP.
 * Returns true if successful, false otherwise. */
static bool
load (const char *file_name, struct intr_frame *if_) { // file_name = 'args-single onearg'
	/* parsing */
	char *token, *save_ptr;
    char *arg_list[100];
    int idx=0;
	for (token = strtok_r (file_name, " ", &save_ptr); token != NULL; token = strtok_r (NULL, " ", &save_ptr))
    {
    	// printf ("************token'%s'\n", token);
        arg_list[idx]=token;
        // printf("************arg_list '%s'\n",arg_list[i]);
		idx++;
    }

	memcpy(file_name,arg_list[0],strlen(arg_list[0])+1);

	struct thread *t = thread_current ();
	struct ELF ehdr;
	struct file *file = NULL;
	off_t file_ofs;
	bool success = false;
	int i;

	/* Allocate and activate page directory. */
	/* 페이지 디렉토리 생성 */
	t->pml4 = pml4_create ();
	if (t->pml4 == NULL)
		goto done;
	/* 페이지 테이블 활성화 */
	process_activate (thread_current ());

	/* Open executable file. */
	/* 프로그램파일 Open */
	file = filesys_open (file_name);
	
	if (file == NULL) {
		printf ("load: %s: open failed\n", file_name);
		goto done;
	}

	/* Project 2 - file_deny_write */
	t->running_file = file;
	file_deny_write(file);

	/* Read and verify executable header. */
	/* ELF파일의 헤더정보를 읽어와 저장*/
	if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
			|| memcmp (ehdr.e_ident, "\177ELF\2\1\1", 7)
			|| ehdr.e_type != 2
			|| ehdr.e_machine != 0x3E // amd64
			|| ehdr.e_version != 1
			|| ehdr.e_phentsize != sizeof (struct Phdr)
			|| ehdr.e_phnum > 1024) {
		printf ("load: %s: error loading executable\n", file_name);
		goto done;
	}

	/* Read program headers. */
	file_ofs = ehdr.e_phoff;
	for (i = 0; i < ehdr.e_phnum; i++) {
		/* 배치정보를 읽어와 저장. */
		struct Phdr phdr;

		if (file_ofs < 0 || file_ofs > file_length (file))
			goto done;
		file_seek (file, file_ofs);

		if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
			goto done;
		file_ofs += sizeof phdr;
		switch (phdr.p_type) {
			case PT_NULL:
			case PT_NOTE:
			case PT_PHDR:
			case PT_STACK:
			default:
				/* Ignore this segment. */
				break;
			case PT_DYNAMIC:
			case PT_INTERP:
			case PT_SHLIB:
				goto done;
			case PT_LOAD:
				if (validate_segment (&phdr, file)) {
					bool writable = (phdr.p_flags & PF_W) != 0;
					uint64_t file_page = phdr.p_offset & ~PGMASK;
					uint64_t mem_page = phdr.p_vaddr & ~PGMASK;
					uint64_t page_offset = phdr.p_vaddr & PGMASK;
					uint32_t read_bytes, zero_bytes;
					if (phdr.p_filesz > 0) {
						/* Normal segment.
						 * Read initial part from disk and zero the rest. */
						read_bytes = page_offset + phdr.p_filesz;
						zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
								- read_bytes);
					} else {
						/* Entirely zero.
						 * Don't read anything from disk. */
						read_bytes = 0;
						zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
					}
					/* 배치정보를통해 파일을 메모리에 적재. */
					if (!load_segment (file, file_page, (void *) mem_page,
								read_bytes, zero_bytes, writable))
						goto done;
				}
				else
					goto done;
				break;
		}
	}

	/* Set up stack. */
	// 스택 초기화
	if (!setup_stack (if_))
		goto done;

	/* Start address. */
	// text세그먼트 시작 주소
	if_->rip = ehdr.e_entry;

	// 인자들을 스택에 삽입(인자 전달)
	/* 유저스택에 프로그램이름과 인자들을 저장하는 함수 */
	/* parse: 프로그램이름과 인자가 저장되어있는 메모리공간, count: 인자의개수, rsp: 스택포인터를가리키는주소 */
	/* argument_stack() 함수를 호출할 시 인자 값을 스택에 오른쪽에서 왼쪽 순으로 저장한다. */
	/* Return Address는 Caller(함수를 호출하는 부분)의 다음 수행 명령어 주소를 의미한다. */
	/* Callee(호출 받은 함수)의 리턴 값은 rax 레지스터에 저장된다. */

	argument_stack(arg_list,idx,if_);

	/* TODO: Your code goes here.
	 * TODO: Implement argument passing (see project2/argument_passing.html). */

	success = true;
	
	// sema_up(&thread_current()->sema_load);
done:
	/* We arrive here whether the load is successful or not. */
	// sema_up(&thread_current()->sema_load);
	// file_close (file);	// process exit에서 수행하도록 수정
	return success;
}

void argument_stack(char **arg_list,int idx,struct intr_frame *if_){

	int i,j;
	int cnt=0;
	int start_addr=if_->rsp;

	for (int i=idx-1; i>-1; i--)
	{
		cnt+=strlen(arg_list[i])+1;
		for (j=strlen(arg_list[i]); j>-1 ; j--)
		{
			if_->rsp=if_->rsp-1;
			memset(if_->rsp, arg_list[i][j], sizeof(char));
		
		}
	
		if (i==0){
	
		/* word-align*/
		int align = 8 - (cnt % 8);
		for (int k=0; k < align ; k++)
		{
			if_->rsp=if_->rsp-1;
			memset(if_->rsp, 0, sizeof(char));
		}

		for (i=idx; i>-1; i--)
		{
			if_->rsp = if_->rsp-8;

			if (i==idx)
				memset(if_->rsp, 0, sizeof(char *));
			else {
				start_addr=start_addr-strlen(arg_list[i])-1;
				memcpy(if_->rsp, &start_addr, sizeof(start_addr));
			}
		}
		if_->rsp = if_->rsp-8;
		memset(if_->rsp, 0, sizeof(void *));
		if_->R.rdi=idx;
		if_->R.rsi=if_->rsp + 8; 
		}
	}
}

/* Checks whether PHDR describes a valid, loadable segment in
 * FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Phdr *phdr, struct file *file) {
	/* p_offset and p_vaddr must have the same page offset. */
	if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
		return false;

	/* p_offset must point within FILE. */
	if (phdr->p_offset > (uint64_t) file_length (file))
		return false;

	/* p_memsz must be at least as big as p_filesz. */
	if (phdr->p_memsz < phdr->p_filesz)
		return false;

	/* The segment must not be empty. */
	if (phdr->p_memsz == 0)
		return false;

	/* The virtual memory region must both start and end within the
	   user address space range. */
	if (!is_user_vaddr ((void *) phdr->p_vaddr))
		return false;
	if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
		return false;

	/* The region cannot "wrap around" across the kernel virtual
	   address space. */
	if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
		return false;

	/* Disallow mapping page 0.
	   Not only is it a bad idea to map page 0, but if we allowed
	   it then user code that passed a null pointer to system calls
	   could quite likely panic the kernel by way of null pointer
	   assertions in memcpy(), etc. */
	if (phdr->p_vaddr < PGSIZE)
		return false;

	/* It's okay. */
	return true;
}

#ifndef VM
/* Codes of this block will be ONLY USED DURING project 2.
 * If you want to implement the function for whole project 2, implement it
 * outside of #ifndef macro. */

/* load() helpers. */
static bool install_page (void *upage, void *kpage, bool writable);

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);

	file_seek (file, ofs);
	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* Get a page of memory. */
		uint8_t *kpage = palloc_get_page (PAL_USER);
		if (kpage == NULL)
			return false;

		/* Load this page. */
		if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes) {
			palloc_free_page (kpage);
			return false;
		}
		memset (kpage + page_read_bytes, 0, page_zero_bytes);

		/* Add the page to the process's address space. */
		if (!install_page (upage, kpage, writable)) {
			printf("fail\n");
			palloc_free_page (kpage);
			return false;
		}

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}
	return true;
}

/* Create a minimal stack by mapping a zeroed page at the USER_STACK */
static bool
setup_stack (struct intr_frame *if_) {
	uint8_t *kpage;
	bool success = false;

	kpage = palloc_get_page (PAL_USER | PAL_ZERO);
	if (kpage != NULL) {
		success = install_page (((uint8_t *) USER_STACK) - PGSIZE, kpage, true);
		if (success)
			if_->rsp = USER_STACK;
		else
			palloc_free_page (kpage);
	}
	return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
 * virtual address KPAGE to the page table.
 * If WRITABLE is true, the user process may modify the page;
 * otherwise, it is read-only.
 * UPAGE must not already be mapped.
 * KPAGE should probably be a page obtained from the user pool
 * with palloc_get_page().
 * Returns true on success, false if UPAGE is already mapped or
 * if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable) {
	struct thread *t = thread_current ();

	/* Verify that there's not already a page at that virtual
	 * address, then map our page there. */
	return (pml4_get_page (t->pml4, upage) == NULL
			&& pml4_set_page (t->pml4, upage, kpage, writable));
}
#else
/* From here, codes will be used after project 3.
 * If you want to implement the function for only project 2, implement it on the
 * upper block. */

static bool
lazy_load_segment (struct page *page, void *aux) {
	/* TODO: Load the segment from the file */
	/* TODO: This called when the first page fault occurs on address VA. */
	/* TODO: VA is available when calling this function. */
}

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);

	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* TODO: Set up aux to pass information to the lazy_load_segment. */
		void *aux = NULL;
		if (!vm_alloc_page_with_initializer (VM_ANON, upage,
					writable, lazy_load_segment, aux))
			return false;

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}
	return true;
}

/* Create a PAGE of stack at the USER_STACK. Return true on success. */
static bool
setup_stack (struct intr_frame *if_) {
	bool success = false;
	void *stack_bottom = (void *) (((uint8_t *) USER_STACK) - PGSIZE);

	/* TODO: Map the stack on stack_bottom and claim the page immediately.
	 * TODO: If success, set the rsp accordingly.
	 * TODO: You should mark the page is stack. */
	/* TODO: Your code goes here */

	return success;
}
#endif /* VM */

/* Project 2 file descriptor */
struct file *process_get_file(int fd)
{
	if (fd < 0 || fd > 63) {
		return NULL;
	}
	struct thread *cur = thread_current();
	if (cur->fdt[fd]==0)
		return NULL;
	else
		return cur->fdt[fd];
}

/* 자식리스트에 접근하여 프로세스 디스크립터 검색*/
struct thread *get_child_process(int pid){
	/* 해당pid가 존재하면 프로세스 디스크립터 반환*/
	/* 리스트에 존재하지않으면 NULL 리턴*/
	struct thread *cur = thread_current();

	struct list_elem *e;

	for (e=list_begin(&cur->child_list); e!=list_end(&cur->child_list); e=list_next(e)){
		struct thread *e_cur = list_entry(e, struct thread, child_elem);	//??? child_elem or elem
		if (pid==e_cur->tid)
			return e_cur;
	}
	return NULL;

}

/*부모프로세스의 자식리스트에서 프로세스 디스크립터 제거*/
void remove_child_process(struct thread *cp){
	/* 자식 리스트에서 제거*/
	list_remove(&cp->child_elem); //??? child_elem or elem

	/* 프로세스 디스크립터 메모리해제???*/
}
