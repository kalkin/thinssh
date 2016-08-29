package main

import (
	"io"
	"io/ioutil"
	"log"
	"os"

	"golang.org/x/crypto/ssh"
)

const REPOS_DIR = "./data/repos"

var (
	hostPrivateKeySigner ssh.Signer
)

func init() {
	keyPath := "./host_key"
	if os.Getenv("HOST_KEY") != "" {
		keyPath = os.Getenv("HOST_KEY")
	}

	hostPrivateKey, err := ioutil.ReadFile(keyPath)
	if err != nil {
		panic(err)
	}

	hostPrivateKeySigner, err = ssh.ParsePrivateKey(hostPrivateKey)
	if err != nil {
		panic(err)
	}
}

func main() {
	config := &ssh.ServerConfig{
		PublicKeyCallback: KeyAuth,
	}
	config.AddHostKey(hostPrivateKeySigner)

	port := "2222"
	if os.Getenv("GIT_SERVER_PORT") != "" {
		port = os.Getenv("GIT_SERVER_PORT")
	}
	host := "0.0.0.0"
	if os.Getenv("GIT_SERVER_HOST") != "" {
		host = os.Getenv("GIT_SERVER_HOST")
	}

	listener := GetListener(host, port)

	for {
		// Once a ServerConfig has been configured, connections can be accepted.
		conn, err := listener.Accept()
		if err != nil {
			log.Println(3, "SSH: Error accepting incoming connection: %v", err)
			continue
		}

		// Before use, a handshake must be performed on the incoming net.Conn.
		// It must be handled in a separate goroutine,
		// otherwise one user could easily block entire loop.
		// For example, user could be asked to trust server key fingerprint and hangs.
		go func() {
			log.Println("SSH: Handshaking for %s", conn.RemoteAddr())
			sConn, chans, reqs, err := ssh.NewServerConn(conn, config)
			if err != nil {
				if err == io.EOF {
					log.Println("SSH: Handshaking was terminated: %v", err)
				} else {
					log.Println(3, "SSH: Error on handshaking: %v", err)
				}
				return
			}

			log.Println("SSH: Connection from %s (%s)", sConn.RemoteAddr(), sConn.ClientVersion())
			// The incoming Request channel must be serviced.
			go ssh.DiscardRequests(reqs)
			go HandleServerConn(sConn.Permissions, chans)
		}()
	}
}