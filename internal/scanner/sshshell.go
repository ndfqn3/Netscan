package scanner

import (
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// SSHInteractive 建立交互式 SSH shell(转发 stdin/stdout, 全交互)
func SSHInteractive(ip string, port int, user, pass string, timeout time.Duration) error {
	config := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password(pass)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         timeout,
	}
	client, err := ssh.Dial("tcp", net.JoinHostPort(ip, itoa(port)), config)
	if err != nil {
		return err
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()

	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}
	if err := session.RequestPty("xterm-256color", 80, 40, modes); err != nil {
		return err
	}
	session.Stdin = os.Stdin
	session.Stdout = os.Stdout
	session.Stderr = os.Stderr
	if err := session.Shell(); err != nil {
		return err
	}
	return session.Wait()
}

// BruteSSHOnce 爆破 SSH 并返回第一个成功凭据
func BruteSSHOnce(ip string, port int, users, passes []string, threads int, timeout time.Duration) (string, string, bool) {
	var mu sync.Mutex
	var foundUser, foundPass string
	found := false
	BruteForce(ip, port, "ssh", users, passes, threads, 0, timeout, func(r BruteResult) {
		mu.Lock()
		if !found {
			found = true
			foundUser = r.Username
			foundPass = r.Password
		}
		mu.Unlock()
	})
	return foundUser, foundPass, found
}
