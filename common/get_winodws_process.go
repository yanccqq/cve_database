package common

import (
	"fmt"
	"syscall"
	"unsafe"
)

type ulong int32
type ulong_ptr uintptr

type PROCESSENTRY32 struct {
	dwSize              ulong
	cntUsage            ulong
	th32ProcessID       ulong
	th32DefaultHeapID   ulong_ptr
	th32ModuleID        ulong
	cntThreads          ulong
	th32ParentProcessID ulong
	pcPriClassBase      ulong
	dwFlags             ulong
	SzExeFile           [260]byte
}

type MODULEENTRY32 struct {
	dwSize        ulong
	th32ModuleID  ulong
	th32ProcessID ulong
	GlblcntUsage  ulong
	ProccntUsage  ulong
	modBaseAddr   byte
	modBaseSize   ulong
	hModule       ulong_ptr
	szModule      [260]byte
	szExePath     [260]byte
}

func GetProcessList() []PROCESSENTRY32 {
	var processArray []PROCESSENTRY32
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	CreateToolhelp32Snapshot := kernel32.NewProc("CreateToolhelp32Snapshot")
	pHandle, _, _ := CreateToolhelp32Snapshot.Call(uintptr(0x2), uintptr(0x0))
	if int(pHandle) == -1 {
		return processArray
	}
	Process32Next := kernel32.NewProc("Process32Next")
	for {
		var proc PROCESSENTRY32
		proc.dwSize = ulong(unsafe.Sizeof(proc))
		if rt, _, _ := Process32Next.Call(uintptr(pHandle), uintptr(unsafe.Pointer(&proc))); int(rt) == 1 {
			processArray = append(processArray, proc)
		} else {
			break
		}
	}
	CloseHandle := kernel32.NewProc("CloseHandle")
	_, _, _ = CloseHandle.Call(pHandle)

	return processArray
}

func GetProcess(pid int) (PROCESSENTRY32, error) {
	var targetProcess PROCESSENTRY32
	targetProcess = PROCESSENTRY32{
		dwSize: 0,
	}

	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	CreateToolhelp32Snapshot := kernel32.NewProc("CreateToolhelp32Snapshot")
	pHandle, _, _ := CreateToolhelp32Snapshot.Call(uintptr(0x2), uintptr(0x0))
	if int(pHandle) == -1 {
		return targetProcess, fmt.Errorf("error:Can not find any proess.")
	}
	Process32Next := kernel32.NewProc("Process32Next")

	for {
		var proc PROCESSENTRY32
		proc.dwSize = ulong(unsafe.Sizeof(proc))
		if rt, _, _ := Process32Next.Call(uintptr(pHandle), uintptr(unsafe.Pointer(&proc))); int(rt) == 1 {
			if int(proc.th32ProcessID) == pid {
				targetProcess = proc
				break
			}
		} else {
			break
		}
	}
	CloseHandle := kernel32.NewProc("CloseHandle")
	_, _, _ = CloseHandle.Call(pHandle)
	return targetProcess, nil
}
