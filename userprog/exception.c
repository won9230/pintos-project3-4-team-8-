#include "userprog/exception.h"
#include <inttypes.h>
#include <stdio.h>
#include "userprog/gdt.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "intrinsic.h"

/* Number of page faults processed. */
static long long page_fault_cnt;

static void kill (struct intr_frame *);
static void page_fault (struct intr_frame *);

/* 사용자 프로그램에 의해 발생할 수 있는 인터럽트에 대한 핸들러를 레지스터에 등록한다.
   (인터럽트가 발생했을 때 등록된 핸들러가 실행된다.)

   실제 UNIX 유사 운영 체제에서 대부분의 인터럽트는 
   [SV-386] 3-24 및 3-25에서 설명한 대로 신호(signal) 형태로 사용자 프로세스에 전달될 것이지만, 
   여기서는 신호를 구현하지 않는다. 
   대신, 이러한 인터럽트가 발생하면 단순히 사용자 프로세스를 강제로 종료시킬 것이다.

   하지만 page fault는 예외다. 현재는 page fault도 다른 예외들과 마찬가지로 처리되고 있다.
   그러나 가상 메모리를 구현하기 위해서는 이 부분을 변경해야 된다.

   Refer to [IA32-v3a] section 5.15 "Exception and Interrupt
   Reference" for a description of each of these exceptions. */
void
exception_init (void) {
	/* 
	 *	아래 3가지의 예외는 사용자 프로그램에서 명시적으로 발생시킬 수 있다. 
	 *	예를 들어, INT, INT3, INTO 및 BOUND 명령을 통해 발생시킬 수 있다. 
	 *	(사용자 프로그램에서는 INT, INT3, INTO 및 BOUND와 같은 명령을 사용하여 
	 *	이러한 예외를 명시적으로 발생시킬 수 있다.) 
	 *	
	 * 	따라서 DPL(Destination Privilege Level)을 3으로 설정한다. 
	 *	이는 사용자 프로그램이 이러한 명령을 통해 이러한 예외를 호출할 수 있도록 허용된다는 의미이다. 
	 *	(사용자 프로그램이 이러한 명령을 사용하여 이러한 예외를 호출할 수 있도록 하기 위해 DPL을 3으로 설정한다.)
	 */
	intr_register_int (3, 3, INTR_ON, kill, "#BP Breakpoint Exception");
	intr_register_int (4, 3, INTR_ON, kill, "#OF Overflow Exception");
	intr_register_int (5, 3, INTR_ON, kill, "#BR BOUND Range Exceeded Exception");

	/* 
	 *	아래의 예외들은 DPL(Destination Privilege Level)이 0으로 설정되어 있어
	 *	사용자 프로세스가 INT 명령을 통해 이러한 예외를 호출하는 것을 방지한다. 
	 *	(특정 예외에 대해서는 사용자 프로세스가 INT 명령을 통해 직접 호출할 수 없도록 DPL을 0으로 설정한다.)
	 */
	intr_register_int (0, 0, INTR_ON, kill, "#DE Divide Error");
	intr_register_int (1, 0, INTR_ON, kill, "#DB Debug Exception");
	intr_register_int (6, 0, INTR_ON, kill, "#UD Invalid Opcode Exception");
	intr_register_int (7, 0, INTR_ON, kill, "#NM Device Not Available Exception");
	intr_register_int (11, 0, INTR_ON, kill, "#NP Segment Not Present");
	intr_register_int (12, 0, INTR_ON, kill, "#SS Stack Fault Exception");
	intr_register_int (13, 0, INTR_ON, kill, "#GP General Protection Exception");
	intr_register_int (16, 0, INTR_ON, kill, "#MF x87 FPU Floating-Point Error");
	intr_register_int (19, 0, INTR_ON, kill, "#XF SIMD Floating-Point Exception");

	/* 
	 *	대부분의 예외는 인터럽트가 활성화된 상태에서 처리될 수 있다.
	 *	하지만 page fault의 경우 인터럽트를 비활성화해야 한다. 
	 *	이는 page fault 주소가 CR2에 저장되고 보존되어야 하기 때문이다. 
	 */
	intr_register_int (14, 0, INTR_OFF, page_fault, "#PF Page-Fault Exception");
}

/* 예외 상황에 대한 통계를 출력한다. (프로그램이 실행되는 동안 발생한 예외에 대한 통계 정보를 출력한다.). */
void
exception_print_stats (void) {
	printf ("Exception: %lld page faults\n", page_fault_cnt);
}

/* 사용자 프로세스에 의해 발생한 예외에 대한 핸들러 함수 */
static void
kill (struct intr_frame *f) {
	/* 
	 *	해당 인터럽트는 사용자 프로세스에 의해 (아마도) 발생한 인터럽트 중 하나이다.(이 인터럽트는 사용자 프로세스에 의해 발생한 것이다.)
	 *	예를 들어 프로세스가 매핑되지 않은 가상 메모리애 접근하려고 시도하는 경우? page fault 예외가 발생할 수 있다.
	 *	이에 대해 현재는 단순히 사용자 프로세스를 강제로 종료 시킨다.
	 *	일반적으로 실제 Unix 유사 운영 체제에서는 예외가 발생했을 때 해당 예외를 신호로 변환하여 다시 프로세스로 전달하는 방식으로 처리된다. 
	 *	그러나 여기서는 신호를 구현하지 않을 것이다
	 */

	/* 
	 *	인터럽트 프레임의 코드 세그먼트 값(f->cs)는 예외가 발생한 위치를 알려준다. 
	 *	인터럽트가 발생한 위치를 알기 위해서 f->cs값을 사용한다 이 값은 예외가 발생한 명령이 위치한 코드 세그먼트를 가리킨다.
	 */
	switch (f->cs) {
		case SEL_UCSEG:
			/* 
			 *	f->cs 가 SEL_UCSEG일 때 사용자 프로세스에서 발생한 예외라고 추측한다.
			 */
			printf ("%s: dying due to interrupt %#04llx (%s).\n", thread_name (), f->vec_no, intr_name (f->vec_no));
			
			intr_dump_frame (f); // 해당 인터럽트의 정보와 레지스터 값을 콘솔에 출력한다.
			thread_exit ();      // 현재 스레드를 종료한다.

		case SEL_KCSEG:
			/* 
			 *	f->cs 가 SEL_KCSEG일 때는 커널 코드 세그먼트인데 예외가 발생했으므로 커널 버그를 뜻한다.
			 *	커널 코드에서는 예외가 발생하면 안된다. page fault는 커널 예외를 발생시킬 수도 있지만 이런 예외까지 도달해서는 안된다.
			 *	이 때 커널을 패닉 상태로 만들어서 이를 강조한다. 
			 *	(커널이 버그를 나타내었을 때, 이를 명확히 보여주기 위해 커널을 패닉 상태로 만듭니다. 
			 *	패닉 상태는 커널이 동작을 멈추고 시스템에 심각한 오류가 발생했음을 나타냅니다.)
			 */
			intr_dump_frame (f); // 해당 인터럽트의 정보와 레지스터 값을 콘솔에 출력한다.
			PANIC ("Kernel bug - unexpected interrupt in kernel"); // 커널을 패닉 상태로 만듬.

		default:
			/* 
			 * 예외가 다른 코드 세그먼트에서 발생하면? 예상한 값이 아니므로 커널을 패닉 상태로 만들고 스레드를 종료한다. 
			 */
			printf ("Interrupt %#04llx (%s) in unknown segment %04x\n", f->vec_no, intr_name (f->vec_no), f->cs);
			thread_exit (); // 현재 스레드를 종료한다.
	}
}

/* 
   Page fault handler. 현재 이 함수는 가상 메모리를 구현하기 위해 채워져야 하는 skeleton code 이다.
   즉, 가상 메모리를 지원하기 위해 페이지 부재 핸들러의 내용을 구현해야 한다. 
   가상 메모리 구현에 필요한 동작 및 로직을 이 코드에 추가해야 합니다.

   프로젝트 2의 일부 해결책은 이 코드를 수정해야 할 수도 있다. 
   프로젝트 2에서 요구되는 특정 솔루션은 이 함수의 코드를 수정해야 할 수도 있다. 
   이는 프로젝트의 요구사항에 따라 코드가 변경될 수 있음을 나타냄.

   페이지 부재 예외가 발생할 때, 오류 주소는 CR2 레지스터에 저장되고, 
   예외에 대한 정보는 F의 error_code 멤버에 포맷팅되어 있다. 
   해당 정보를 해석하는 방법은 예제 코드에서 확인할 수 있으며, 
   더 자세한 정보는 [IA32-v3a]의 "Interrupt 14--Page Fault Exception (#PF)" 설명에서 찾을 수 있다. */
static void
page_fault (struct intr_frame *f) {
	bool not_present;  /* True: 존재하지 않는 페이지, false: 존재하지만 읽기 전용 페이지 */
	bool write;        /* True: 페이지에 대한 접근이 쓰기로 발생한 경우, false: 읽기로 발생한 경우 */
	bool user;         /* True: 사용자에 의한 접근, false: 커널에 의한 접근 */
	void *fault_addr;  /* page fault가 발생한 주소를 저장하는 포인터 변수 */

	/* 
	 * 발생한 예외로 인해 접근하려고 한 가상 주소를 가지고 온다.
	 * 이 주소는 코드영역 OR 데이터 영역을 가리킬 수 있다.
	 * 이 주소가 꼭 예외를 발생시킨 명령어의 주소를 의미하는 것은 아니다. 
	 * 예외를 발생시킨 명령어의 주소는 f->rip에 저장되어 있다.
	 * 즉 fault_addr 과 f->rip는 일치하지 않을 수 있다.
	 */

	fault_addr = (void *) rcr2();

	/*
	 * 인터럽트를 다시 활성화 한다. 
	 * 이전에 인터럽트가 비활성화 된 이유 : CR2 레지스터를 읽어야 했기 때문이다. 
	 * 위 rcr2 함수에서 CR2 레지스터를 읽어들였으므로 인터러브를 다시 활성화한다.
	 */
	intr_enable ();


	/* page fault 예외가 발생한 원인을 판단한다. */
	not_present = (f->error_code & PF_P) == 0;
	write = (f->error_code & PF_W) != 0;
	user = (f->error_code & PF_U) != 0;



#ifdef VM
	// 만약 Project3를 성공적으로 수행하여 vm_try_handle_falut()를 구현 했다면? 
	// 아래 코드를 통해서 page fault를 처리한다.
	if (vm_try_handle_fault (f, fault_addr, user, write, not_present))
		return;
#endif
	// Project3 수행 전이라면 아래 코드를 통해 page fault 처리한다.

	/* page_fault_cnt 변수를 증가시켜 페이지 부재 횟수를 기록한다.*/
	page_fault_cnt++;

	/* 
	 * 페이지 부재가 발생한 상황을 콘솔에 출력한다. 
	 * 발생한 페이지 부재의 주소, 
	 * 부재의 종류 (존재하지 않는 페이지인지, 권한 위반이 있는 페이지인지),
	 * 액세스 종류 (쓰기인지 읽기인지), 
	 * 그리고 액세스를 수행한 컨텍스트 (사용자 모드인지 커널 모드인지)를 출력한다.
	 */
	printf ("Page fault at %p: %s error %s page in %s context.\n",
			fault_addr,
			not_present ? "not present" : "rights violation",
			write ? "writing" : "reading",
			user ? "user" : "kernel");

	// 현재 실행 중인 프로세스를 죵료한다. (page fault 발생한 경우 프로세스를 종료하는 것으로 처리한다.)
	kill (f);
}

