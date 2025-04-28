package reporter

import (
	"errors"
	"io"

	"github.com/YutaroHayakawa/bgplay/internal/bgputils"
	"github.com/YutaroHayakawa/bgplay/pkg/bgpcap"
)

func Report(w io.Writer, f *bgpcap.File) error {
	for {
		msg, err := f.ReadMsg()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return err
		}
		bgputils.PrintMessage(w, msg)
	}
	return nil
}
