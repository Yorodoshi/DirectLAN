package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"directlan/internal/coordinator"
	"directlan/internal/processcontrol"
)

func main() {
	listen := flag.String("listen", ":8443", "listen address")
	state := flag.String("state", "coordinator-state.json", "state file path")
	cert := flag.String("tls-cert", "", "TLS certificate PEM file")
	key := flag.String("tls-key", "", "TLS private key PEM file")
	devHTTP := flag.Bool("dev-http-loopback", false, "allow plain HTTP on a loopback address for local development")
	httpsRelay := flag.Bool("https-relay", false, "enable authenticated WebSocket relay for WireGuard ciphertext")
	stopEvent := flag.String("stop-event", "", "launcher-owned Windows event for graceful shutdown")
	flag.Parse()

	if *devHTTP {
		host, _, err := net.SplitHostPort(*listen)
		if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
			slog.Error("development HTTP must bind to a numeric loopback address")
			os.Exit(2)
		}
	} else if *cert == "" || *key == "" {
		slog.Error("TLS certificate and key are required outside loopback development mode")
		os.Exit(2)
	}

	store, err := coordinator.OpenStore(*state)
	if err != nil {
		slog.Error("cannot open coordinator state", "error", err)
		os.Exit(1)
	}
	handler := coordinator.NewServer(store, *devHTTP)
	handler.EnableHTTPSRelay = *httpsRelay
	server := &http.Server{
		Addr:              *listen,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      35 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS13},
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	closeWatch, watchErr := processcontrol.Watch(ctx, *stopEvent, stop)
	if watchErr != nil {
		slog.Error("launcher shutdown event", "error", watchErr)
		os.Exit(1)
	}
	defer closeWatch()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			slog.Error("coordinator shutdown", "error", err)
		}
	}()
	slog.Info("coordinator listening", "address", *listen, "development_http", *devHTTP)
	if *devHTTP {
		err = server.ListenAndServe()
	} else {
		err = server.ListenAndServeTLS(*cert, *key)
	}
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("coordinator server stopped", "error", err)
		os.Exit(1)
	}
}
