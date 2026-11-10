//go:build windows

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"directlan/internal/mesh"
	"directlan/internal/processcontrol"
	"directlan/internal/service"
	"golang.org/x/sys/windows/svc"
)

func main() {
	programData := os.Getenv("ProgramData")
	if programData == "" {
		programData = filepath.Join(os.Getenv("SystemDrive"), "ProgramData")
	}
	var cfg service.Config
	var stunURLs string
	var stopEvent string
	pair := flag.Bool("direct-pair", false, "start serverless two-PC WireGuard pairing")
	flag.StringVar(&stopEvent, "stop-event", "", "launcher-owned Windows event for graceful shutdown")
	flag.StringVar(&cfg.CoordinatorURL, "coordinator", "", "HTTPS URL of DirectLAN coordinator")
	flag.StringVar(&cfg.IdentityPath, "identity", filepath.Join(programData, "DirectLAN", "identity.dat"), "DPAPI-encrypted identity path")
	flag.StringVar(&cfg.AllowedUISID, "ui-sid", "", "Windows user SID allowed to control the named pipe")
	flag.StringVar(&cfg.DeviceName, "device-name", "", "human-readable device name")
	flag.BoolVar(&cfg.DevHTTP, "dev-http-loopback", false, "allow plaintext coordinator only on loopback for tests")
	flag.StringVar(&cfg.Transport, "transport", "https", "https (default), auto (ICE then HTTPS), or direct")
	flag.StringVar(&cfg.CAPath, "coordinator-ca", "", "optional PEM CA trusted only by DirectLAN")
	flag.BoolVar(&cfg.Padding, "padding", true, "use randomized length padding inside HTTPS relay")
	flag.StringVar(&stunURLs, "stun", "", "comma-separated STUN URLs for internet NAT traversal")
	flag.Parse()
	for _, raw := range strings.Split(stunURLs, ",") {
		if value := strings.TrimSpace(raw); value != "" {
			cfg.STUNURLs = append(cfg.STUNURLs, value)
		}
	}
	if !*pair && cfg.CoordinatorURL == "" {
		log.Fatal("-coordinator is required")
	}
	isService, err := svc.IsWindowsService()
	if err != nil {
		log.Fatal(err)
	}
	if isService {
		if *pair {
			log.Fatal("direct pairing is launched by the DirectLAN desktop app")
		}
		if cfg.AllowedUISID == "" {
			log.Fatal("Windows service requires explicit -ui-sid")
		}
		if err := svc.Run("DirectLAN", &windowsService{cfg: cfg}); err != nil {
			log.Fatal(err)
		}
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	closeWatch, err := processcontrol.Watch(ctx, stopEvent, stop)
	if err != nil {
		log.Fatal(err)
	}
	defer closeWatch()
	if *pair {
		if err := mesh.Run(ctx, cfg.IdentityPath, cfg.AllowedUISID); err != nil {
			log.Fatal(err)
		}
		return
	}
	instance, err := service.New(cfg)
	if err != nil {
		log.Fatal(err)
	}
	log.Print("DirectLAN IPC listening on \\.\\pipe\\DirectLAN")
	if err := instance.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		log.Fatal(err)
	}
}

type windowsService struct{ cfg service.Config }

func (w *windowsService) Execute(_ []string, requests <-chan svc.ChangeRequest, updates chan<- svc.Status) (bool, uint32) {
	updates <- svc.Status{State: svc.StartPending}
	instance, err := service.New(w.cfg)
	if err != nil {
		log.Print(fmt.Errorf("start DirectLAN: %w", err))
		return true, 1
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- instance.Run(ctx) }()
	updates <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case request := <-requests:
			switch request.Cmd {
			case svc.Interrogate:
				updates <- request.CurrentStatus
			case svc.Stop, svc.Shutdown:
				updates <- svc.Status{State: svc.StopPending}
				cancel()
				select {
				case err := <-done:
					if err != nil {
						log.Print(err)
					}
				case <-time.After(20 * time.Second):
					log.Print("timed out stopping DirectLAN")
				}
				return false, 0
			}
		case err := <-done:
			if err != nil {
				log.Print(err)
				return true, 1
			}
			return false, 0
		}
	}
}
