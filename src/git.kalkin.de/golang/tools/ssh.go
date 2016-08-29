package tools

import (
	"crypto/sha256"
	"fmt"
	"github.com/mattn/go-shellwords"
	"golang.org/x/crypto/ssh"
	"io"
	"log"
	"net"
	"os/exec"
	"path/filepath"
	"strings"
)

const ID_DIR = "./data/id/"
const ORG_DIR = "./data/repos"
const BIN_DIR = "./bin"

func PublicKeyStr(pubkey ssh.PublicKey) string {
	h := sha256.New()
	h.Write(pubkey.Marshal())
	return fmt.Sprintf("%x", h.Sum(nil))
}

func KeyAuth(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	log.Println(conn.RemoteAddr(), "authenticate with", key.Type())
	p := &ssh.Permissions{}
	p.CriticalOptions = make(map[string]string)
	p.CriticalOptions["fingerprint"] = PublicKeyStr(key)
	return p, nil
}

func GetListener(host string, port string) net.Listener {
	addr := host + ":" + port
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("failed to listen on %s", addr)
	}
	log.Printf("listening on %s", addr)
	return listener
}

func HandleServerConn(permissions *ssh.Permissions, chans <-chan ssh.NewChannel) {
	id := permissions.CriticalOptions["fingerprint"]
	for newChan := range chans {
		if newChan.ChannelType() != "session" {
			newChan.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}

		ch, reqs, err := newChan.Accept()
		if err != nil {
			log.Println(3, "Error accepting channel: %v", err)
			continue
		}
		go func(in <-chan *ssh.Request) {
			defer ch.Close()
			for req := range in {
				switch req.Type {
				case "exec":
					execCmd, err := execute(id, req)
					if err != nil {
						sendErrToClient(ch, req, err)
						return
					}
					stdout, err := execCmd.StdoutPipe()
					if err != nil {
						sendErrToClient(ch, req, err)
						return
					}
					stderr, err := execCmd.StderrPipe()
					if err != nil {
						sendErrToClient(ch, req, err)
						return
					}
					stdin, err := execCmd.StdinPipe()
					if err != nil {
						sendErrToClient(ch, req, err)
						return
					}

					err = execCmd.Start()
					if err != nil {
						sendErrToClient(ch, req, err)
						return
					}

					reply(req, true)
					go io.Copy(stdin, ch)
					io.Copy(ch, stdout)
					io.Copy(ch.Stderr(), stderr)
					// teardown session
					if p, err := execCmd.Process.Wait(); err != nil {
						sendErrToClient(ch, req, err)
						return
					} else {
						log.Printf("Exit %s", p.Exited())
						log.Printf("Success %s", p.Success())
						log.Println("Closing Channel")
						ch.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
						return
					}
				default:
					log.Println("Not exec moving on")
				}
			}
		}(reqs)

	}

}

func execute(id string, req *ssh.Request) (*exec.Cmd, error) {
	full_string := string(req.Payload[4:])
	cmd, err := shellwords.Parse(full_string)
	if err != nil {
		return nil, err
	}
	if err = validateCommand(cmd[0]); err != nil {
		return nil, err
	}
	log.Printf("%d", cmd)
	execCmd := exec.Command(BIN_DIR+"/"+cmd[0], cmd[1:]...)
	execCmd.Env = append(execCmd.Env, fmt.Sprintf("USER_TOKEN=%s", id))
	return execCmd, nil
}

func reply(req *ssh.Request, b bool) {
	if req.WantReply {
		log.Printf("Sending reply %s", b)
		req.Reply(b, nil)
	}
}

func sendErrToClient(channel ssh.Channel, req *ssh.Request, err error) {
	msg := fmt.Sprintf("%s", err)
	io.WriteString(channel.Stderr(), msg)
	reply(req, false)
}

func validateCommand(command string) error {
	command = BIN_DIR + "/" + command
	allowedCmds, err := filepath.Glob(BIN_DIR + "/[:alnum:]*")
	if err != nil {
		return err
	}

	for _, cmd := range allowedCmds {
		if command == "./"+cmd {
			return nil
		}
	}
	return fmt.Errorf("not a valid command %s\n", command)

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
