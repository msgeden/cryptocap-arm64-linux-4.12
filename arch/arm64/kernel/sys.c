/*
 * AArch64-specific system calls implementation
 *
 * Copyright (C) 2012 ARM Ltd.
 * Author: Catalin Marinas <catalin.marinas@arm.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <linux/compiler.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/export.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <asm/cpufeature.h>

asmlinkage long sys_mmap(unsigned long addr, unsigned long len,
			 unsigned long prot, unsigned long flags,
			 unsigned long fd, off_t off)
{
	if (offset_in_page(off) != 0)
		return -EINVAL;

	return sys_mmap_pgoff(addr, len, prot, flags, fd, off >> PAGE_SHIFT);
}

SYSCALL_DEFINE1(arm64_personality, unsigned int, personality)
{
	if (personality(personality) == PER_LINUX32 &&
		!system_supports_32bit_el0())
		return -EINVAL;
	return sys_personality(personality);
}


//#ifdef TARGET_CRYPTO_CAP
SYSCALL_DEFINE2(dgrant, uint64_t, pc_arg, uint64_t, sp_el0_arg) {
    
    printk(KERN_INFO "dgrant entry\n");
    uint64_t pc, sp, ttbr0_el1, ttbr1_el1, current_task_struct, pstate, tpidr_el0, tpidrro_el0, tcr_el1, sctlr_el1, mair_el1;
    pc=pc_arg;
    sp=sp_el0_arg;
 
    asm volatile (
        "mrs x9, ttbr0_el1\n\t"
        "str x9, %0\n\t"
        : "=m" (ttbr0_el1)
        : 
        : "x9"
    );
    asm volatile (
        "mrs x9, ttbr1_el1\n\t"
        "str x9, %0\n\t"
        : "=m" (ttbr1_el1)
        : 
        : "x9"
    );
    asm volatile (
        "mrs x9, tpidr_el1\n\t"
        "str x9, %0\n\t"
        : "=m" (current_task_struct)
        : 
        : "x9"
    );
    
    // asm volatile (
    //     "mov x9, sp\n\t"
    //     "str x9, %0\n\t"
    //     : "=m" (current_task_struct) //current (task_struct) addresss here
    //     : 
    //     : "x9"
    // );

    // asm volatile (
    //     "mov x9, sp\n\t"
    //     "str x9, %0\n\t"
    //     : "=m" (sp_el1)
    //     : 
    //     : "x9"
    // );

    asm volatile (
        "mrs x9, spsr_el1 \n\t"
        "str x9, %0\n\t"
        : "=m" (pstate)
        : 
        : "x9"
    );
    asm volatile (
        "mrs x9, tpidr_el0\n\t"
        "str x9, %0\n\t"
        : "=m" (tpidr_el0)
        : 
        : "x9"
    );
    asm volatile (
        "mrs x9, tpidrro_el0\n\t"
        "str x9, %0\n\t"
        : "=m" (tpidrro_el0)
        : 
        : "x9"
    );
    asm volatile (
        "mrs x9, tcr_el1\n\t"
        "str x9, %0\n\t"
        : "=m" (tcr_el1)
        : 
        : "x9"
    );
    asm volatile (
        "mrs x9, sctlr_el1\n\t"
        "str x9, %0\n\t"
        : "=m" (sctlr_el1)
        : 
        : "x9"
    );
    asm volatile (
        "mrs x9, mair_el1\n\t"
        "str x9, %0\n\t"
        : "=m" (mair_el1)
        : 
        : "x9"
    );


    // Set DCLC register fields 
    asm volatile (
            "ldr x9, %0\n\t"
            ".word 0x3600089\n\t"      // cmovcl dclc[0]/PC, x9
            :
            :"m"(pc)
            :"x9" // clobber list 
    ); 
    asm volatile (
            "ldr x9, %0\n\t"
            ".word 0x3600289\n\t"      // cmovcl dclc[1]/SP, x9
            :
            :"m"(sp)
            :"x9" // clobber list 
    ); 
    asm volatile (
            "ldr x9, %0\n\t"
            ".word 0x3600489\n\t"      // cmovcl dclc[2]/TTBR0_EL1, x9
            :
            :"m"(ttbr0_el1)
            :"x9" // clobber list 
    ); 
    asm volatile (
            "ldr x9, %0\n\t"
            ".word 0x3600689\n\t"      // cmovcl dclc[3]/TTBR1_EL1, x9
            :
            :"m"(ttbr1_el1)
            :"x9" // clobber list 
    ); 
    asm volatile (
            "ldr x9, %0\n\t"
            ".word 0x3600889\n\t"      // cmovcl dclc[4]/CURRENT_TASK_STRUCT-TPIDR_EL1, x9
            :
            :"m"(current_task_struct)
            :"x9" // clobber list 
    ); 
    asm volatile (
            "ldr x9, %0\n\t"
            ".word 0x3600a89\n\t"      // cmovcl dclc[5]/PSTATE, x9
            :
            :"m"(pstate)
            :"x9" // clobber list 
    ); 
    asm volatile (
            "ldr x9, %0\n\t"
            ".word 0x3600c89\n\t"      // cmovcl dclc[6]/TPIDR_EL0, x9
            :
            :"m"(tpidr_el0)
            :"x9" // clobber list 
    ); 
     //tpidrro_el0=current->thread.cpu_context.sp;
     asm volatile (
            "ldr x9, %0\n\t"
            ".word 0x3600e89\n\t"      // cmovcl dclc[7]/TPIDRRO_EL0, x9
            :
            :"m"(tpidrro_el0)
            :"x9" // clobber list 
    ); 
    asm volatile (
            "ldr x9, %0\n\t"
            ".word 0x3601089\n\t"      // cmovcl dclc[8]/TCR_EL1, x9
            :
            :"m"(tcr_el1)
            :"x9" // clobber list 
    ); 
    asm volatile (
            "ldr x9, %0\n\t"
            ".word 0x3601289\n\t"      // cmovcl dclc[7]/SCTLR_EL1, x9
            :
            :"m"(sctlr_el1)
            :"x9" // clobber list 
    ); 
    asm volatile (
            "ldr x9, %0\n\t"
            ".word 0x3601489\n\t"      // cmovcl dclc[7]/MAIR_EL1, x9
            :
            :"m"(mair_el1)
            :"x9" // clobber list 
    ); 
    printk(KERN_INFO "dgrant termination\n");
    return 0;
}  
SYSCALL_DEFINE3(read_cap, unsigned int, fd, char __user *, buf, size_t, count){
    printk(KERN_INFO "read_cap entry\n");
    printk(KERN_INFO "read_cap termination\n");
    return 0;
}
SYSCALL_DEFINE3(write_cap, unsigned int, fd, const char __user *, buf,
		size_t, count){
    printk(KERN_INFO "write_cap entry\n");
    printk(KERN_INFO "write_cap termination\n");
    return 0;
}
SYSCALL_DEFINE1(pipe_cap, int __user *, fildes){
    printk(KERN_INFO "pipe_cap entry\n");
    printk(KERN_INFO "pipe_cap termination\n");
    return 0;
}
SYSCALL_DEFINE2(dup2_cap, unsigned int, oldfd, unsigned int, newfd){
    printk(KERN_INFO "dup2_cap entry\n");
    printk(KERN_INFO "dup2_cap termination\n");
    return 0;
}
//#endif	



/*
 * Wrappers to pass the pt_regs argument.
 */
asmlinkage long sys_rt_sigreturn_wrapper(void);
#define sys_rt_sigreturn	sys_rt_sigreturn_wrapper
#define sys_personality		sys_arm64_personality

#undef __SYSCALL
#define __SYSCALL(nr, sym)	[nr] = sym,

/*
 * The sys_call_table array must be 4K aligned to be accessible from
 * kernel/entry.S.
 */
void * const sys_call_table[__NR_syscalls] __aligned(4096) = {
	[0 ... __NR_syscalls - 1] = sys_ni_syscall,
#include <asm/unistd.h>
};
