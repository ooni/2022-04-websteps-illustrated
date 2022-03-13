//go:build linux
// +build linux

package main

import (
	"os/user"
	"strconv"
	"syscall"

	"github.com/bassosimone/websteps-illustrated/internal/model"
	"github.com/bassosimone/websteps-illustrated/internal/runtimex"
)

func getcurrent() *user.User {
	pwent, err := user.Current()
	runtimex.PanicOnError(err, "user.Current failed")
	return pwent
}

func isroot() bool {
	return getuid(getcurrent()) == 0
}

func getpwent(name string) *user.User {
	pwent, err := user.Lookup(name)
	runtimex.PanicOnError(err, "user.Lookup failed")
	return pwent
}

func getuid(pwent *user.User) int {
	uid, err := strconv.Atoi(pwent.Uid)
	runtimex.PanicOnError(err, "strconv.Atoi failed for Uid")
	return uid
}

func getgid(pwent *user.User) int {
	gid, err := strconv.Atoi(pwent.Gid)
	runtimex.PanicOnError(err, "strconv.Atoi failed for Gid")
	return gid
}

func dropgid(newGid int) {
	err := syscall.Setresgid(newGid, newGid, newGid)
	runtimex.PanicOnError(err, "syscall.Setresgid failed")
}

func dropuid(newUid int) {
	err := syscall.Setresuid(newUid, newUid, newUid)
	runtimex.PanicOnError(err, "syscall.Setresuid failed")
}

func dropprivileges(logger model.Logger) {
	if !isroot() {
		return
	}
	pwent := getpwent("nobody")
	dropgid(getgid(pwent))
	dropuid(getuid(pwent))
	logger.Infof("dropped privileges to %+v", pwent)
}
