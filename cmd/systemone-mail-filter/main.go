package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/joho/godotenv"

	"github.com/fr3akX/systemone-mail-filter/internal/config"
	"github.com/fr3akX/systemone-mail-filter/internal/filter"
	"github.com/fr3akX/systemone-mail-filter/internal/jev"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if err := run(log); err != nil {
		log.Error("systemone-mail-filter failed", "error", err.Error())
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	configPath := flag.String("config", "", "JSON configuration file (otherwise built-in defaults)")
	envPath := flag.String("env-file", ".env", "dotenv file; existing environment takes precedence; empty disables loading")
	mode := flag.String("mode", "serve", "serve, classify (JSON), or filter (rewritten message)")
	input := flag.String("input", "-", "RFC 5322 file for classify/filter; - reads stdin")
	from := flag.String("envelope-from", "", "optional SMTP envelope sender for classify/filter")
	check := flag.Bool("check", false, "validate configuration without contacting Jev or starting SMTP")
	flag.Parse()
	if flag.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	if *mode != "serve" && *mode != "classify" && *mode != "filter" {
		return errors.New("mode must be serve, classify, or filter")
	}
	if *check {
		log.Info("configuration valid")
		return nil
	}
	if *envPath != "" {
		if err := godotenv.Load(*envPath); err != nil && !(*envPath == ".env" && errors.Is(err, os.ErrNotExist)) {
			return errors.New("cannot load dotenv file")
		}
	}
	key := os.Getenv("JEV_KEY")
	if key == "" {
		return errors.New("JEV_KEY is required (environment or dotenv file)")
	}
	processor := &filter.Processor{Config: cfg, Classifier: jev.New(cfg, key)}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if *mode == "serve" {
		return filter.Serve(ctx, &filter.Backend{Processor: processor, Relay: filter.SMTPRelay{Config: cfg}, Log: log})
	}
	var r io.Reader = os.Stdin
	if *input != "-" {
		f, err := os.Open(*input)
		if err != nil {
			return err
		}
		defer f.Close()
		r = f
	}
	raw, err := io.ReadAll(io.LimitReader(r, cfg.MaxMessageBytes+1))
	if err != nil {
		return err
	}
	if int64(len(raw)) > cfg.MaxMessageBytes {
		return fmt.Errorf("message exceeds max_message_bytes")
	}
	out, report, err := processor.Process(ctx, raw, *from)
	if *mode == "classify" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if encodeErr := enc.Encode(report); encodeErr != nil {
			return encodeErr
		}
		if report.Result == nil {
			return errors.New("classification unavailable")
		}
	}
	if err != nil {
		return err
	}
	if *mode == "filter" {
		_, err = os.Stdout.Write(out)
	}
	return err
}
