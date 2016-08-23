package main

import (
	"crypto/sha256"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

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

func keyAuth(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	log.Println(conn.RemoteAddr(), "authenticate with", key.Type())
	p := &ssh.Permissions{}
	p.CriticalOptions = make(map[string]string)
	p.CriticalOptions["fingerprint"] = publicKeyStr(key)
	return p, nil
}

func publicKeyStr(pubkey ssh.PublicKey) string {
	h := sha256.New()
	h.Write(pubkey.Marshal())
	return fmt.Sprintf("%x", h.Sum(nil))
}

func main() {
	config := &ssh.ServerConfig{
		PublicKeyCallback: keyAuth,
	}
	config.AddHostKey(hostPrivateKeySigner)

	port := ":2222"
	if os.Getenv("PORT") != "" {
		port = os.Getenv("PORT")
	}
	socket, err := net.Listen("tcp", port)
	if err != nil {
		log.Fatalf("failed to listen on *:%s", port)
	}
	log.Printf("listening on %s", port)
	for {
		conn, err := socket.Accept()
		if err != nil {
			log.Printf("failed to accept incoming connection (%s)", err)
			continue
		}

		// From a standard TCP connection to an encrypted SSH connection
		sshConn, chans, reqs, err := ssh.NewServerConn(conn, config)
		if err != nil {
			log.Printf("failed to handshake (%s)", err)
			continue
		}
		defer sshConn.Close()

		log.Printf("new ssh connection from %s (%s)", sshConn.RemoteAddr(), sshConn.ClientVersion())
		// Print incoming out-of-band Requests
		go handleRequests(sshConn.Permissions, reqs)
		// Accept all channels
		go handleChannels(sshConn.Permissions, chans)
	}
}
func handleRequests(permissions *ssh.Permissions, reqs <-chan *ssh.Request) {
	log.Printf("Fingerprint: %s", permissions.CriticalOptions["fingerprint"])
	for req := range reqs {
		log.Printf("recieved out-of-band request: %+v", req)
	}
}

func handleChannels(permissions *ssh.Permissions, chans <-chan ssh.NewChannel) {
	// Service the incoming Channel channel.
	id := permissions.CriticalOptions["fingerprint"]
	for newChannel := range chans {
		// Channels have a type, depending on the application level
		// protocol intended. In the case of a shell, the type is
		// "session" and ServerShell may be used to present a simple
		// terminal interface.
		if t := newChannel.ChannelType(); t != "session" {
			newChannel.Reject(ssh.UnknownChannelType, fmt.Sprintf("unknown channel type: %s", t))
			continue
		}
		channel, requests, err := newChannel.Accept()
		if err != nil {
			log.Printf("could not accept channel (%s)", err)
			continue
		}

		// Sessions have out-of-band requests such as "shell", "pty-req" and "env"
		go func(in <-chan *ssh.Request) {
			for req := range in {
				ok := false

				switch req.Type {
				case "env":
					handleEnv(channel, req)
					ok = true
				case "exec":
					command, ns, name := handleExec(id, channel, req)
					cmd := exec.Command(command, id, ns, name)
					cmd.Stdout = channel
					cmd.Stderr = channel
					cmd.Stdin = channel

					err := cmd.Start()
					if err != nil {
						log.Printf("could not start command (%s)", err)
						continue
					}

					// teardown session
					go func() {
						_, err := cmd.Process.Wait()
						if err != nil {
							log.Printf("failed to exit bash (%s)", err)
						}
						channel.Close()
						log.Printf("session closed")
					}()

					ok = true
				default:
					log.Println(req.Type)
					log.Println(string(req.Payload))
					msg := "request type '" + req.Type + "' is not 'exec'\r\n"
					log.Println(msg)
					ok = true
				}

				if !ok {
					log.Printf("declining %s request...", req.Type)
				}

				req.Reply(ok, nil)
			}
		}(requests)
		defer channel.Close()
	}
}

func handleEnv(channel ssh.Channel, req *ssh.Request) {
	log.Println("Handling env")
	payload := strings.Split(string(req.Payload[4:]), "\n")
	env_var := payload[0]
	log.Println(env_var)
	if len(payload) > 1 {
		env_val := payload[1]
		log.Println(env_val)
	}
	if req.WantReply {
		log.Println("Want reply")
	}
}

// Payload: int: command size, string: command
func handleExec(id string, ch ssh.Channel, req *ssh.Request) (string, string, string) {
	full_string := string(req.Payload[4:])
	log.Println(full_string)
	foo := strings.Split(full_string, " ")
	command := foo[0]
	log.Printf("Handling exec %s", command)
	gitCmds := []string{"git-receive-pack", "git-upload-pack"}

	if len(foo) != 2 {
		ch.Write([]byte("usage: git-receive-pack <git-dir>\r\n"))
		log.Println("no repo specified")
		ch.Close()
		return "", "", ""
	}

	repo, repo_err := git_repo_str(foo[1])
	if repo_err != nil {
		log.Println(repo_err)
		ch.Write([]byte("invalid repo path\r\n"))
		ch.Close()
		return "", "", ""
	}
	namespace, repo_name := filepath.Split(repo)
	namespace = strings.Trim(namespace, "/")
	repo_name = strings.Trim(repo_name, "/")

	valid := false
	for _, cmd := range gitCmds {
		if command == cmd {
			valid = true
		}
	}
	if !valid {
		ch.Write([]byte("command is not a GIT command\r\n"))
		ch.Close()
		return "", "", ""
	}

	return "./bin/" + command, namespace, repo_name
}

func git_repo_str(unescaped_path string) (string, error) {
	unescaped_path = filepath.ToSlash(unescaped_path)
	unescaped_path = strings.Trim(unescaped_path, ".'\"/")
	if strings.Count(unescaped_path, "/") != 1 {
		return "", fmt.Errorf("invalid path to many slashes")
	}
	if unescaped_path[0] == '.' {
		return "", fmt.Errorf("invalid path")
	}
	return filepath.Clean(unescaped_path), nil
}
