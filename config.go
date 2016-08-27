package main

import (
	"fmt"
	"github.com/go-yaml/yaml"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
)

const DEFAULT_CONFIG = `---
host: localhost
port: 2222
...`

type Config struct {
	Host string
	Port string
}

func GetConfig() Config {
	c := getDefaultConfig()
	path, err := getConfigFile()
	if err != nil {
		return c
	} else {
		data, err := ioutil.ReadFile(path)
		if err != nil {
			log.Fatal(err)
		}
		err = yaml.Unmarshal(data, &c)
		if err != nil {
			log.Panicf("eror: %v", err)
		}
		return c
	}
}

func getDefaultConfig() Config {
	var c Config
	err := yaml.Unmarshal([]byte(DEFAULT_CONFIG), &c)
	if err != nil {
		log.Panicf("eror: %v", err)
	}
	return c
}

func getConfigFile() (string, error) {
	home := os.Getenv("HOME")
	if home == "" {
		log.Panic("No HOME dir set")
	}

	loctions := [5]string{
		filepath.Join(home, ".config/thinssh/config"),
		filepath.Join(home, ".thinssh/config"),
		filepath.Join(home, ".thinsshrc"),
		filepath.Join("/etc/thinssh/config"),
		filepath.Join("/etc/thinsshrc"),
	}

	config_home := os.Getenv("XDG_CONFIG_HOME")

	if config_home != "" {
		config_home = filepath.Join(config_home, "thinssh/config")
		if configExists(config_home) {
			return config_home, nil
		}
	}
	for _, f := range loctions {
		if configExists(f) {
			return f, nil
		}
	}
	return "", fmt.Errorf("No config exists")
}

func configExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func PrintDefaultConfig() {
	c := getDefaultConfig()
	PrintConfig(c)
}

func PrintConfig(c Config) {
	println("---")
	result, err := yaml.Marshal(&c)
	if err != nil {
		log.Panicf("error: %v", err)
	}
	print(string(result))
	println("...")
}
