// Copyright 2018 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package kernel

import (
	"reflect"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/abi/sentry"
	"gvisor.dev/gvisor/pkg/bpf"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/arch"
)

const (
	maxSyscallFilterInstructions = 1 << 15

	// uncacheableBPFAction is an invalid seccomp action code.
	// It is used as a sentinel value in `taskSeccompFilters.cache` to indicate
	// that a specific syscall number is uncachable.
	uncacheableBPFAction = linux.SECCOMP_RET_ACTION_FULL
)

// taskSeccomp holds seccomp-related data for a `Task`.
type taskSeccomp struct {
	// filters is the list of seccomp programs that are applied to the task,
	// in the order in which they were installed.
	filters []bpf.Program

	// cache maps syscall numbers to the action to take for that syscall number.
	// It is only populated for syscalls where determining this action does not
	// involve any input data other than the architecture and the syscall
	// number in any of `filters`.
	// If any other input is necessary, the cache stores `uncacheableBPFAction`
	// to indicate that this syscall number's rules are not cacheable.
	cache [sentry.MaxSyscallNum + 1]linux.BPFAction
}

// copy returns a copy of this `taskSeccomp`.
func (ts *taskSeccomp) copy() *taskSeccomp {
	return &taskSeccomp{
		filters: append(([]bpf.Program)(nil), ts.filters...),
		cache:   ts.cache,
	}
}

// dataAsBPFInput returns a serialized BPF program, only valid on the current task
// goroutine.
//
// Note: this is called for every syscall, which is a very hot path.
func dataAsBPFInput(t *Task, d *linux.SeccompData) bpf.Input {
	buf := t.CopyScratchBuffer(d.SizeBytes())
	d.MarshalUnsafe(buf)
	return buf[:d.SizeBytes()]
}

func seccompSiginfo(t *Task, errno, sysno int32, ip hostarch.Addr) *linux.SignalInfo {
	si := &linux.SignalInfo{
		Signo: int32(linux.SIGSYS),
		Errno: errno,
		Code:  linux.SYS_SECCOMP,
	}
	si.SetCallAddr(uint64(ip))
	si.SetSyscall(sysno)
	si.SetArch(t.SyscallTable().AuditNumber)
	return si
}

// checkSeccompSyscall applies the task's seccomp filters before the execution
// of syscall sysno at instruction pointer ip. (These parameters must be passed
// in because vsyscalls do not use the values in t.Arch().)
//
// Preconditions: The caller must be running on the task goroutine.
func (t *Task) checkSeccompSyscall(sysno int32, args arch.SyscallArguments, ip hostarch.Addr) linux.BPFAction {
	result := linux.BPFAction(t.evaluateSyscallFilters(sysno, args, ip))
	action := result & linux.SECCOMP_RET_ACTION
	switch action {
	case linux.SECCOMP_RET_TRAP:
		// "Results in the kernel sending a SIGSYS signal to the triggering
		// task without executing the system call. ... The SECCOMP_RET_DATA
		// portion of the return value will be passed as si_errno." -
		// Documentation/prctl/seccomp_filter.txt
		t.SendSignal(seccompSiginfo(t, int32(result.Data()), sysno, ip))
		// "The return value register will contain an arch-dependent value." In
		// practice, it's ~always the syscall number.
		t.Arch().SetReturn(uintptr(sysno))

	case linux.SECCOMP_RET_ERRNO:
		// "Results in the lower 16-bits of the return value being passed to
		// userland as the errno without executing the system call."
		t.Arch().SetReturn(-uintptr(result.Data()))

	case linux.SECCOMP_RET_TRACE:
		// "When returned, this value will cause the kernel to attempt to
		// notify a ptrace()-based tracer prior to executing the system call.
		// If there is no tracer present, -ENOSYS is returned to userland and
		// the system call is not executed."
		if !t.ptraceSeccomp(result.Data()) {
			// This useless-looking temporary is needed because Go.
			tmp := uintptr(unix.ENOSYS)
			t.Arch().SetReturn(-tmp)
			return linux.SECCOMP_RET_ERRNO
		}

	case linux.SECCOMP_RET_ALLOW:
		// "Results in the system call being executed."

	case linux.SECCOMP_RET_KILL_THREAD:
		// "Results in the task exiting immediately without executing the
		// system call. The exit status of the task will be SIGSYS, not
		// SIGKILL."

	default:
		// consistent with Linux
		return linux.SECCOMP_RET_KILL_THREAD
	}
	return action
}

func (t *Task) evaluateSyscallFilters(sysno int32, args arch.SyscallArguments, ip hostarch.Addr) uint32 {
	ret := uint32(linux.SECCOMP_RET_ALLOW)
	s := t.seccomp.Load()
	if s == nil {
		return ret
	}
	ts := s.(*taskSeccomp)
	if sysno >= 0 && sysno <= sentry.MaxSyscallNum {
		if cached := ts.cache[sysno]; cached != uncacheableBPFAction {
			return uint32(cached)
		}
	}

	data := linux.SeccompData{
		Nr:                 sysno,
		Arch:               t.image.st.AuditNumber,
		InstructionPointer: uint64(ip),
	}
	// data.args is []uint64 and args is []arch.SyscallArgument (uintptr), so
	// we can't do any slicing tricks or even use copy/append here.
	for i, arg := range args {
		if i >= len(data.Args) {
			break
		}
		data.Args[i] = arg.Uint64()
	}
	input := dataAsBPFInput(t, &data)

	// "Every filter successfully installed will be evaluated (in reverse
	// order) for each system call the task makes." - kernel/seccomp.c
	for i := len(ts.filters) - 1; i >= 0; i-- {
		thisRet, err := bpf.Exec[bpf.NativeEndian](ts.filters[i], input)
		if err != nil {
			t.Debugf("seccomp-bpf filter %d returned error: %v", i, err)
			thisRet = uint32(linux.SECCOMP_RET_KILL_THREAD)
		}
		// "If multiple filters exist, the return value for the evaluation of a
		// given system call will always use the highest precedent value." -
		// Documentation/prctl/seccomp_filter.txt
		//
		// (Note that this contradicts prctl(2): "If the filters permit prctl()
		// calls, then additional filters can be added; they are run in order
		// until the first non-allow result is seen." prctl(2) is incorrect.)
		//
		// "The ordering ensures that a min_t() over composed return values
		// always selects the least permissive choice." -
		// include/uapi/linux/seccomp.h
		if (thisRet & linux.SECCOMP_RET_ACTION) < (ret & linux.SECCOMP_RET_ACTION) {
			ret = thisRet
		}
	}

	return ret
}

// populateCache recomputes `ts.cache` from `ts.filters`.
func (ts *taskSeccomp) populateCache(t *Task) {
	// Look up Nr and Arch fields, we'll use their offsets later
	// to verify whether they were accessed.
	sd := linux.SeccompData{}
	sdType := reflect.TypeOf(sd)
	nrField, ok := sdType.FieldByName("Nr")
	if !ok {
		panic("linux.SeccompData.Nr field not found")
	}
	archField, ok := sdType.FieldByName("Arch")
	if !ok {
		panic("linux.SeccompData.Arch field not found")
	}

	for sysno := int32(0); sysno <= sentry.MaxSyscallNum; sysno++ {
		sd.Nr = sysno
		sd.Arch = t.image.st.AuditNumber
		input := dataAsBPFInput(t, &sd)
		isCacheable := true
		ret := linux.BPFAction(linux.SECCOMP_RET_ALLOW)
		// See notes in `evaluateSyscallFilters` for how to properly interpret
		// seccomp filter and results. We use the same approach here: iterate
		// through filters backwards, and take the smallest result.
	nextFilter:
		for i := len(ts.filters) - 1; i >= 0; i-- {
			exec, err := bpf.InstrumentedExec[bpf.NativeEndian](ts.filters[i], input)
			if err != nil {
				isCacheable = false
				break
			}
			for offset, accessed := range exec.InputAccessed {
				if !accessed {
					continue // Input byte not accessed by the program.
				}
				if uintptr(offset) >= nrField.Offset && uintptr(offset) < nrField.Offset+nrField.Type.Size() {
					continue // The program accessed the "Nr" field, this is OK.
				}
				if uintptr(offset) >= archField.Offset && uintptr(offset) < archField.Offset+archField.Type.Size() {
					continue // The program accessed the "Arch" field, this is OK.
				}
				isCacheable = false
				break nextFilter
			}
			if (linux.BPFAction(exec.ReturnValue) & linux.SECCOMP_RET_ACTION) < (ret & linux.SECCOMP_RET_ACTION) {
				ret = linux.BPFAction(exec.ReturnValue)
			}
		}
		if isCacheable {
			ts.cache[sysno] = ret
		} else {
			ts.cache[sysno] = uncacheableBPFAction
		}
	}
}

// AppendSyscallFilter adds BPF program p as a system call filter.
//
// Preconditions: The caller must be running on the task goroutine.
func (t *Task) AppendSyscallFilter(p bpf.Program, syncAll bool) error {
	// While syscallFilters are an atomic.Value we must take the mutex to prevent
	// our read-copy-update from happening while another task is syncing syscall
	// filters to us, this keeps the filters in a consistent state.
	t.tg.signalHandlers.mu.Lock()
	defer t.tg.signalHandlers.mu.Unlock()

	// Cap the combined length of all syscall filters (plus a penalty of 4
	// instructions per filter beyond the first) to maxSyscallFilterInstructions.
	// This restriction is inherited from Linux.
	totalLength := p.Length()
	newSeccomp := &taskSeccomp{}

	if s := t.seccomp.Load(); s != nil {
		ts := s.(*taskSeccomp)
		for _, f := range ts.filters {
			totalLength += f.Length() + 4
		}
		newSeccomp.filters = append(newSeccomp.filters, ts.filters...)
	}

	if totalLength > maxSyscallFilterInstructions {
		return linuxerr.ENOMEM
	}

	newSeccomp.filters = append(newSeccomp.filters, p)
	newSeccomp.populateCache(t)
	t.seccomp.Store(newSeccomp)

	if syncAll {
		// Note: No new privs is always assumed to be set.
		for ot := t.tg.tasks.Front(); ot != nil; ot = ot.Next() {
			if ot != t {
				ot.seccomp.Store(newSeccomp.copy())
			}
		}
	}

	return nil
}

// SeccompMode returns a SECCOMP_MODE_* constant indicating the task's current
// seccomp syscall filtering mode, appropriate for both prctl(PR_GET_SECCOMP)
// and /proc/[pid]/status.
func (t *Task) SeccompMode() int {
	f := t.seccomp.Load()
	if f != nil && len(f.(*taskSeccomp).filters) > 0 {
		return linux.SECCOMP_MODE_FILTER
	}
	return linux.SECCOMP_MODE_NONE
}
