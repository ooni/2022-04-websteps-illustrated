//go:build linux
// +build linux

package main

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
	"syscall"

	"github.com/bassosimone/websteps-illustrated/internal/runtimex"
)

func getcurrent() *user.User {
	pwent, err := user.Current()
	runtimex.Must(err, "user.Current failed")
	return pwent
}

func isroot() bool {
	return getuid(getcurrent()) == 0
}

func getpwent(name string) *user.User {
	pwent, err := user.Lookup(name)
	runtimex.Must(err, "user.Lookup failed")
	return pwent
}

func getuid(pwent *user.User) int {
	uid, err := strconv.Atoi(pwent.Uid)
	runtimex.Must(err, "strconv.Atoi failed for Uid")
	return uid
}

func getgid(pwent *user.User) int {
	gid, err := strconv.Atoi(pwent.Gid)
	runtimex.Must(err, "strconv.Atoi failed for Gid")
	return gid
}

func dropgid(newGid int) {
	err := syscall.Setresgid(newGid, newGid, newGid)
	runtimex.Must(err, "syscall.Setresgid failed")
}

func dropuid(newUid int) {
	err := syscall.Setresuid(newUid, newUid, newUid)
	runtimex.Must(err, "syscall.Setresuid failed")
}

func dropprivileges(user string) {
	if !isroot() {
		return
	}
	pwent := getpwent(user)
	dropgid(getgid(pwent))
	dropuid(getuid(pwent))
	fmt.Fprintf(os.Stderr, "dropped privileges to %+v\n", pwent)
}
