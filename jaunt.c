/*
 * libjaunt
 * Copyright (C) 2017 <decatf@gmail.com>
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#define LOG_TAG "libjaunt"

#include <dlfcn.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <ucontext.h>
#include <pthread.h>
#include <cutils/log.h>
#include <sys/prctl.h>

#include "jaunt.h"

void* libtcg_arm_handle = NULL;
static int initialized = 0;

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

int (*init_tcg_arm)(void);
void (*exec)(
	uint32_t *regs, uint64_t* fpregs,
    uint32_t *cpsr, uint32_t *fpscr,
    uint32_t *fpexc,
    int dump_reg);

void sig_handler(int signal, siginfo_t *info, void *context);

union {
	void (*ill_sigaction) (int signal, siginfo_t *info, void *context);
	void (*ill_handler)(int signal);
} ill_handlers;
char ill_is_siginfo;

struct sigaction old_sa, new_sa = {
	.sa_flags     = SA_SIGINFO,
	.sa_sigaction = &sig_handler
};

int (*orig_sigaction)(int signum, const struct sigaction *act,
		struct sigaction *oldact);

/* void ( *(*orig_signal)(int signum, void (*handler)(int)) ) (int); */
sighandler_t (*orig_signal)(int signum, sighandler_t handler);

/* void ( *signal(int signum, void (*handler)(int)) ) (int) */
__attribute__ ((visibility ("default")))
sighandler_t bsd_signal(int signum, sighandler_t handler)
{
	/* Ignore other signal handlers */
	if (signum == SIGILL)
	{
		sighandler_t ret;
		if (ill_is_siginfo)
		{
			/* idk */
			ret = SIG_DFL;
		}
		else
		{
			ret = ill_handlers.ill_handler;
		}

		ill_is_siginfo = 0;
		if (handler == SIG_DFL || handler == SIG_ERR)
		{
			ill_handlers.ill_handler = NULL;
		}
		else
		{
			ill_handlers.ill_handler = handler;
		}

		return ret;
	}

	return orig_signal(signum, handler);
}

__attribute__ ((visibility ("default")))
int sigaction(int signum, const struct sigaction *act,
		struct sigaction *oldact)
{
	if (signum == SIGILL)
	{
		if (oldact != NULL)
		{
			memset((void*)oldact, 0, sizeof(*oldact));
			if (ill_is_siginfo)
			{
				oldact->sa_flags = SA_SIGINFO;
				oldact->sa_sigaction = ill_handlers.ill_sigaction;
			}
			else
			{
				oldact->sa_flags = 0;
				oldact->sa_handler = ill_handlers.ill_handler;
			}
		}

		if (act != NULL)
		{
			if (act->sa_flags & SA_SIGINFO)
			{
				ill_is_siginfo = 1;
				ill_handlers.ill_sigaction = act->sa_sigaction;
			}
			else
			{
				ill_is_siginfo = 0;
				ill_handlers.ill_handler = act->sa_handler ? act->sa_handler : SIG_DFL;
			}
		}
		return 0;
	}

	return orig_sigaction(signum, act, oldact);
}

void init_arm_tcg_lib(void)
{
	int res;

	if (likely(libtcg_arm_handle != NULL))
		return;

	pthread_mutex_lock(&mutex);

	void *handle = dlopen("libtcg_arm.so", RTLD_NOW | RTLD_LOCAL);
	if (!handle) {
		ALOGE("Error loading libtcg_arm.so: %s", dlerror());
		pthread_mutex_unlock(&mutex);
		return;
	}

	init_tcg_arm = dlsym(handle, "init_tcg_arm");
	exec = dlsym(handle, "exec");

	if (init_tcg_arm == NULL || exec == NULL) {
		ALOGE("Error loading symbols from libtcg_arm.so");
		pthread_mutex_unlock(&mutex);
		return;
	}

	res = init_tcg_arm();

	if (!res) {
		libtcg_arm_handle = handle;
		initialized = 1;
	} else {
		ALOGE("init_tcg_arm() returned %d", res);
	}

	pthread_mutex_unlock(&mutex);
}

static inline int check_vfp_magic(struct vfp_sigframe *vfp) {
	return vfp->magic == VFP_MAGIC;
}

void sig_handler(int signal, siginfo_t *info, void *context) {
	struct sigcontext *uc_mcontext = &((ucontext_t*)context)->uc_mcontext;
	struct aux_sigframe *aux = (struct aux_sigframe*)&((ucontext_t*)context)->uc_regspace;
	struct vfp_sigframe *vfp = (struct vfp_sigframe*)aux;

	if (signal != SIGILL && info->si_code != ILL_ILLOPC) return;

	/* One time init*/
	init_arm_tcg_lib();

	if (unlikely(!initialized)) {
		ALOGE("ARM emulation unit not initialized.\n");
		abort();
	}

	if (unlikely(!check_vfp_magic(vfp))) {
		ALOGE("VFP Magic check failed. magic = 0x%lX\n", vfp->magic);
		abort();
	}

	/* Thumb mode? */
	if (uc_mcontext->arm_cpsr & (1 << 5))
	{
		/* Sometimes the instruction pointer gets in the middle
		 * of the NEON instruction:
		 * (gdb) x/2i $pc-6
		 * 0x5dd27280:  bl      0x5db4940c
		 * 0x5dd27284:  vldr    d16, [r4]
		 * The PC here is at 0x5dd27286, which decodes instruction
		 * to "lsls r0, r0, #12". I don't know the real reasons
		 * why this happens.
		 *
		 * To workaround this, we use a set of bitmasks & values
		 * to check for the faulting instruction. If it is, we
		 * decrement the PC register by 2.
		 *
		 * This is the result from fuzzer. Masks are generated using
		 * 'espresso' program. */

		static const struct
		{
			uint32_t mask;
			uint32_t val;
		} insns[] = {
			{ 0xfd200f21, 0xed200a21 },
			{ 0xfc2c0f60, 0xec200b60 },
			{ 0xff9ffe00, 0xec100a00 },
			{ 0xfd5ffe10, 0xec588a10 },
			{ 0xff9ffe00, 0xec111a00 },
			{ 0xff9ffe00, 0xec122a00 },
			{ 0xff9ffe00, 0xec144a00 },
			{ 0xfd5ffe10, 0xec599a10 },
			{ 0xfd5ffe10, 0xec5aaa10 },
			{ 0xfd5ffe10, 0xec5cca10 },
			{ 0xff9ffe00, 0xec133a00 },
			{ 0xff9ffe00, 0xec155a00 },
			{ 0xff9ffe00, 0xec166a00 },
			{ 0xfd5bbe10, 0xec5bba10 },
			{ 0xfd5dde10, 0xec5dda10 },
			{ 0xfcee0f40, 0xece60a40 },
			{ 0xfd5eee10, 0xec5eea10 },
			{ 0xff977e00, 0xec177a00 },
			{ 0xfd609e0e, 0xed609a0e },
			{ 0xfc608f11, 0xec208a11 },
			{ 0xfd60de06, 0xed60da06 },
			{ 0xfd60be0a, 0xed60ba0a },
			{ 0xfd60ce07, 0xed60ca00 },
			{ 0xfd60ae0c, 0xed60aa0c },
			{ 0xfd60fe01, 0xed60fa00 },
			{ 0xfde01e1e, 0xecc01a1e },
			{ 0xfde05e16, 0xecc05a16 },
			{ 0xfde03e1a, 0xecc03a1a },
			{ 0xfde07e12, 0xecc07a12 },
			{ 0xfd209f0f, 0xed209a0f },
			{ 0xfd20df07, 0xed20da07 },
			{ 0xfd20bf0b, 0xed20ba0b },
			{ 0xfd20af0d, 0xed20aa0d },
			{ 0xfd20ff03, 0xed20fa03 },
			{ 0xff409e1e, 0xec409a0e },
			{ 0xfcaf0e40, 0xeca60a40 },
			{ 0xfda01f1f, 0xec801a1f },
			{ 0xfdc08f11, 0xec808a11 },
			{ 0xff40de16, 0xec40da06 },
			{ 0xff40be1a, 0xec40ba0a },
			{ 0xfda05f17, 0xec805a17 },
			{ 0xfc2e0f60, 0xec2c0b60 },
			{ 0xfc2a0f60, 0xec220b60 },
			{ 0xfda03f1b, 0xec803a1b },
			{ 0xff40ce17, 0xec40ca00 },
			{ 0xff40ae1c, 0xec40aa0c },
			{ 0xff40fe12, 0xec40fa02 },
			{ 0xfc290f60, 0xec200b60 },
			{ 0xfda07f13, 0xec807a13 },
			{ 0xff40ee14, 0xec40ea04 },
			{ 0xfde02e1c, 0xecc02a1c },
			{ 0xfc601f1f, 0xec201a1f },
			{ 0xfc4a0f10, 0xec4a0b00 },
			{ 0xfc4a0f10, 0xec400b00 },
			{ 0xfde06e14, 0xecc06a14 },
			{ 0xfc605f17, 0xec205a17 },
			{ 0xfc603f1b, 0xec203a1b },
			{ 0xfd20ee08, 0xed20ea08 },
			{ 0xfc604f19, 0xec204a19 },
			{ 0xfc602f1d, 0xec202a1d },
			{ 0xfd20fe04, 0xed20fa04 },
			{ 0xfc607f13, 0xec207a13 },
			{ 0xfd20cf09, 0xed20ca09 },
			{ 0xfd208e20, 0xed208a20 },
			{ 0xfc606f15, 0xec206a15 },
			{ 0xfd20ef05, 0xed20ea05 },
			{ 0xff009f1f, 0xec009a0f },
			{ 0xff00df17, 0xec00da07 },
			{ 0xff00bf1b, 0xec00ba0b },
			{ 0xff008e30, 0xec008a20 },
			{ 0xfdc0ce10, 0xec80ca10 },
			{ 0xff00cf19, 0xec00ca09 },
			{ 0xff00af1d, 0xec00aa0d },
			{ 0xff00ff13, 0xec00fa03 },
			{ 0xff403e1c, 0xec003a1c },
			{ 0xfdc06e18, 0xec806a18 },
			{ 0xff00ef15, 0xec00ea05 },
			{ 0xff407e14, 0xec007a14 },
			{ 0xfda02f1d, 0xec802a1d },
			{ 0xfda06f15, 0xec806a15 },
			{ 0xfd20be0c, 0xed20ba0c },
			{ 0xfe601e1e, 0xec601a1e },
			{ 0xfd60ee03, 0xed60ea00 },
			{ 0xfd204e20, 0xed204a20 },
			{ 0xfe480e10, 0xee480a10 },
			{ 0xfd200f3e, 0xed200b00 },
			{ 0xfe605e16, 0xec605a16 },
			{ 0xfe603e1a, 0xec603a1a },
			{ 0xff9f0e00, 0xec1f0a00 },
			{ 0xfe604e18, 0xec604a18 },
			{ 0xfe602e1c, 0xec602a1c },
			{ 0xfe607e12, 0xec607a12 },
			{ 0xfe606e14, 0xec606a14 },
			{ 0xff004e30, 0xec004a20 },
			{ 0xfdc0ae10, 0xec80aa10 },
			{ 0xff000e2f, 0xec000a2f },
			{ 0xff002e30, 0xec002a20 },
			{ 0xff405e18, 0xec005a18 },
			{ 0xfde04e18, 0xecc04a18 },
			{ 0xfcae0ec0, 0xeca60a40 },
			{ 0xfd20ae0e, 0xed20aa0e },
			{ 0xfe608e10, 0xec608a10 },
			{ 0xfd20ee06, 0xed20ea06 },
			{ 0xfd20de08, 0xed20da08 },
			{ 0xfe600e20, 0xec600a20 },
			{ 0xfda02e1e, 0xec802a1e },
			{ 0xfda06e16, 0xec806a16 },
			{ 0xff409e10, 0xec009a10 },
			{ 0xfdc04e1c, 0xec804a1c },
			{ 0xff00be1c, 0xec00ba0c },
			{ 0xff001e30, 0xec001a20 },
			{ 0xfe440e10, 0xee440a10 },
			{ 0xfcaf0e40, 0xeca90a40 },
			{ 0xfe100f20, 0xee000b20 },
			{ 0xff00ee18, 0xec00ea08 },
			{ 0xff400e1f, 0xec400a00 },
			{ 0xfda04f19, 0xec804a19 },
			{ 0xff00fe14, 0xec00fa04 },
			{ 0xfd20ce0c, 0xed20ca0c },
			{ 0xfe203e1c, 0xec203a1c },
			{ 0xfe206e18, 0xec206a18 },
			{ 0xfe207e14, 0xec207a14 },
			{ 0xff00ae1e, 0xec00aa0e },
			{ 0xff00ee16, 0xec00ea06 },
			{ 0xfd200e3f, 0xed200a00 },
			{ 0xfdc08e18, 0xec808a18 },
			{ 0xff00de18, 0xec00da08 },
			{ 0xff000f31, 0xec000a21 },
			{ 0xfe20ce10, 0xec20ca10 },
			{ 0xfd20ce0a, 0xed20ca0a },
			{ 0xfe420e10, 0xee420a10 },
			{ 0xfe202e1e, 0xec202a1e },
			{ 0xfe206e16, 0xec206a16 },
			{ 0xfe20ae10, 0xec20aa10 },
			{ 0xfe205e18, 0xec205a18 },
			{ 0xfda04e1a, 0xec804a1a },
			{ 0xfdc08e14, 0xec808a14 },
			{ 0xff00ce1c, 0xec00ca0c },
			{ 0xff000e38, 0xec000a28 },
			{ 0xfde08e10, 0xecc08a10 },
			{ 0xfe202e20, 0xec202a20 },
			{ 0xfe209e10, 0xec209a10 },
			{ 0xfe204e1c, 0xec204a1c },
			{ 0xfcc00f10, 0xec400b00 },
			{ 0xff00ce1a, 0xec00ca0a },
			{ 0xfd90fe10, 0xec10fa10 },
			{ 0xff000e34, 0xec000a24 },
			{ 0xfd200f80, 0xec000b80 },
			{ 0xfe204e1a, 0xec204a1a },
			{ 0xfd200e80, 0xed200a80 },
			{ 0xfe201e20, 0xec201a20 },
			{ 0xfec00e10, 0xee800a10 },
			{ 0xfe208e18, 0xec208a18 },
			{ 0xfc440f10, 0xec400b00 },
			{ 0xfda08e12, 0xec808a12 },
			{ 0xff000e32, 0xec000a22 },
			{ 0xfca00f80, 0xec200b80 },
			{ 0xfd600e50, 0xec400a50 },
			{ 0xfc600f10, 0xec600b10 },
			{ 0xfe200e28, 0xec200a28 },
			{ 0xfe208e14, 0xec208a14 },
			{ 0xfd000f50, 0xec000b50 },
			{ 0xfe600e10, 0xee400a10 },
			{ 0xfe810e10, 0xee800a10 },
			{ 0xfe208e12, 0xec208a12 },
			{ 0xfe200e24, 0xec200a24 },
			{ 0xfda00e30, 0xec800a30 },
			{ 0xfd800f20, 0xec000b20 },
			{ 0xfda00f10, 0xec200a10 },
			{ 0xfc600e30, 0xec200a30 },
			{ 0xfcc00f40, 0xecc00b00 },
			{ 0xfe200e22, 0xec200a22 },
			{ 0xfc200e90, 0xec200a90 },
			{ 0xfda00e40, 0xec800a40 },
			{ 0xfe200e40, 0xec200a40 },
			{ 0xfd400f00, 0xed400b00 },
			{ 0xffc00e00, 0xec000a00 },
			{ 0xfeb00e00, 0xee900a00 },
			{ 0xfda00e00, 0xeda00a00 },
			{ 0xfeb00e10, 0xeea00a00 },
			{ 0xff800e10, 0xec000a00 },
			{ 0xff000e80, 0xec000a80 },
			{ 0xff000f3e, 0xec000b00 },
			{ 0xff000e3f, 0xec000a00 },
			{ 0xef000e00, 0xef000a00 },
		};

		uint16_t insn = *(uint16_t*)uc_mcontext->arm_pc;
		/* I think this can cause a page fault, but that's very unlikely. */
		uint16_t insn2 = *(uint16_t*)(uc_mcontext->arm_pc-2);
		uint32_t insn_full = (insn2 << 16) | insn;

		for (size_t i = 0; i < sizeof(insns)/sizeof(*insns); ++i)
		{
			if ((insn_full & insns[i].mask) == insns[i].val)
			{
				uc_mcontext->arm_pc -= 2;
				break;
			}
		}
	}

	unsigned long prev_pc = uc_mcontext->arm_pc;

	exec(
		(uint32_t*)&uc_mcontext->arm_r0,
		(uint64_t*)vfp->ufp.fpregs,
		(uint32_t*)&uc_mcontext->arm_cpsr,
		(uint32_t*)&vfp->ufp.fpscr,
		(uint32_t*)&vfp->ufp_exc.fpexc,
		0);

	/* No NEON instructions was found - abort execution */
	if (unlikely(prev_pc == uc_mcontext->arm_pc))
	{
		/* Invoke the saved signal handler */
		if (ill_is_siginfo)
		{
			if (ill_handlers.ill_sigaction == NULL)
			{
				/* We will return to the same instruction where
				 * fault happed, so signal will be raised again */
				orig_signal(signal, SIG_DFL);
				return;
			}

			ill_handlers.ill_sigaction(signal, info, context);
		}
		else
		{
			if (ill_handlers.ill_handler == NULL)
			{
				orig_signal(signal, SIG_DFL);
				return;
			}
			else if (ill_handlers.ill_handler == SIG_IGN)
			{
				return;
			}

			ill_handlers.ill_handler(signal);
		}
	}
}

static void *handle;
void __attribute__ ((constructor)) init(void) {
	handle = dlopen("libc.so", RTLD_LAZY);
	*(void**) (&orig_sigaction) = dlsym(handle, "sigaction");
	*(void**) (&orig_signal) = dlsym(handle, "bsd_signal");
	orig_sigaction(SIGILL, &new_sa, &old_sa);
}

void __attribute__ ((destructor)) finish(void) {
	orig_sigaction(SIGILL, &old_sa, &new_sa);
	dlclose(handle);
}
