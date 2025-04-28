package recorder

import (
	"errors"
	"fmt"
	"net"

	"github.com/YutaroHayakawa/bgplay/pkg/bgpcap"
)

func Record(resultCh chan error, conn *Conn, f *bgpcap.File) {
	if conn == nil {
		resultCh <- fmt.Errorf("recorder connection is not provided")
	}

	if f == nil {
		resultCh <- fmt.Errorf("bgpcap file is not provided")
	}

	go func() {
		for {
			msg, err := conn.Read()
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					resultCh <- nil
					return
				}
				resultCh <- fmt.Errorf("failed to read BGP message: %w", err)
				return
			}
			if err := f.WriteMsg(msg); err != nil {
				resultCh <- fmt.Errorf("failed to write BGP message: %w", err)
				return
			}
		}
	}()
}
