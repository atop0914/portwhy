// Command holdport holds a real socket so the rehearsal can assert what a probe
// says about a state the script created itself.
//
// A rehearsal must not depend on the kernel state of whatever machine runs it —
// that is the difference between a script people keep and one they delete after
// the second false red. The probe is the one command that reads the live kernel,
// so instead of hoping some port is busy, the script makes one busy:
//
//	holdport -port-file /tmp/p            # a listening socket, port written to the file
//	holdport -port-file /tmp/p -timewait  # a port left in TIME_WAIT
//
// It writes the port number and blocks until SIGTERM/SIGINT, so the caller kills
// it rather than guessing how long to sleep.
package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"
)

func main() {
	portFile := flag.String("port-file", "", "file to write the chosen port into")
	timeWait := flag.Bool("timewait", false, "leave the port in TIME_WAIT instead of holding a listener")
	flag.Parse()

	if *portFile == "" {
		fatal(fmt.Errorf("-port-file is required"))
	}

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port

	if *timeWait {
		// The side that closes first is the side that waits out 2×MSL, so the
		// server closes before the client. Closing the listener last leaves the
		// port itself in TIME_WAIT, which is exactly the state a probe is asked
		// about.
		done := make(chan struct{})
		go func() {
			conn, err := ln.Accept()
			if err != nil {
				close(done)
				return
			}
			_ = conn.Close()
			close(done)
		}()
		client, err := net.Dial("tcp4", ln.Addr().String())
		if err != nil {
			fatal(err)
		}
		<-done
		_ = client.Close()
		// The listener has to go before the port can be in TIME_WAIT and not in
		// LISTEN: the kernel keeps the listener's row while it is open.
		_ = ln.Close()
		time.Sleep(100 * time.Millisecond)
	} else {
		// Accept in the background: an unaccepted connection is still a connection,
		// but a listener that never accepts is not the shape being rehearsed.
		go func() {
			for {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				_ = conn.Close()
			}
		}()
	}

	if err := os.WriteFile(*portFile, []byte(strconv.Itoa(port)), 0o644); err != nil {
		fatal(err)
	}
	// Also on stderr, so a failing run's log says which port it was.
	fmt.Fprintf(os.Stderr, "holdport: %d\n", port)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	<-sig
	if !*timeWait {
		_ = ln.Close()
	}
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "holdport: %v\n", err)
	os.Exit(1)
}
