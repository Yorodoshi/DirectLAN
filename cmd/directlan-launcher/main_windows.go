//go:build windows

package main

import (
	"golang.org/x/sys/windows"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"unsafe"
)

var defaultMode = "mesh"

func main() {
	exe, err := os.Executable()
	if err != nil {
		showError(err.Error())
		return
	}
	ui := filepath.Join(filepath.Dir(exe), "ui", "DirectLAN.exe")
	if _, err := os.Stat(ui); err != nil {
		showError("Распакуйте весь архив DirectLAN в одну папку. Не найден файл ui\\DirectLAN.exe.")
		return
	}
	command := exec.Command(ui, "--launch", defaultMode)
	command.Dir = filepath.Dir(exe)
	command.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if err := command.Start(); err != nil {
		showError(err.Error())
	}
}

func showError(message string) {
	text, _ := windows.UTF16PtrFromString(message)
	title, _ := windows.UTF16PtrFromString("DirectLAN — запуск")
	windows.NewLazySystemDLL("user32.dll").NewProc("MessageBoxW").Call(0, uintptr(unsafe.Pointer(text)), uintptr(unsafe.Pointer(title)), 0x10)
}
