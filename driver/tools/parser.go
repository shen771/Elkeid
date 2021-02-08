package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/jessevdk/go-flags"
)

var opts struct {
	Input  string            `short:"i" long:"input" description:"Input pipe path" required:"true" default:"/proc/hids_driver/1"`
	Filter map[string]string `short:"f" long:"filter" description:"Filter map such as: -f \"data_type:42\" -f \"uid:0\""`
}

func main() {
	_, err := flags.ParseArgs(&opts, os.Args)
	if err != nil {
		return
	}
	pipe, err := os.Open(opts.Input)
	if err != nil {
		fmt.Println(err)
		return
	}
	s := bufio.NewScanner(pipe)
	s.Split(func(data []byte, atEOF bool) (advance int, token []byte, err error) {
		if atEOF && len(data) == 0 {
			return 0, nil, nil
		}
		if i := bytes.IndexByte(data, '\x17'); i >= 0 {
			return i + 1, data[0:i], nil
		}
		if atEOF {
			return len(data), data, nil
		}
		// Request more data.
		return 0, nil, nil
	})
	for s.Scan() {
		fields := strings.Split(s.Text(), "\x1e")
		verbose := true
		if len(fields) > 10 {
			for k, v := range opts.Filter {
				switch k {
				case "uid":
					verbose = (v == fields[0]) && verbose
				case "data_type":
					verbose = (v == fields[1]) && verbose
				case "exe":
					verbose = (v == fields[2]) && verbose
				case "pid":
					verbose = (v == fields[3]) && verbose
				case "ppid":
					verbose = (v == fields[4]) && verbose
				case "pgid":
					verbose = (v == fields[5]) && verbose
				case "tgid":
					verbose = (v == fields[6]) && verbose
				case "sid":
					verbose = (v == fields[7]) && verbose
				case "comm":
					verbose = (v == fields[8]) && verbose
				case "nodename":
					verbose = (v == fields[9]) && verbose
				case "sessionid":
					verbose = (v == fields[10]) && verbose
				}
			}
		}
		if verbose {
			output, _ := json.Marshal(fields)
			fmt.Println(string(output))
		}
	}
}
