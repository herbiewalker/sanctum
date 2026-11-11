// ╭──────────────────────────────────────────────────────────────────╮
// │  ┌●───●───●───●───●───●───●───●───●───●───●───●───●───●───●───┐  │
// │  │                                                            │  │
// │  ●   ██╗  ██╗    ██╗    ██╗                                   ●  │
// │  │   ██║  ██║    ██║    ██║           herbiewalker            │  │
// │  │   ███████║    ██║ █╗ ██║──●──●──●──┐                       │  │
// │  │   ██╔══██║    ██║███╗██║           │                       │  │
// │  ●   ██║  ██║    ╚███╔███╔╝           ●───⏣  code · tools     ●  │
// │  │   ╚═╝  ╚═╝     ╚══╝╚══╝                    homelab         │  │
// │  │                                                            │  │
// │  └●───●───●───●───●───●───●───●───●───●───●───●───●───●───●───┘  │
// ╰──────────────────────────────────────────────────────────────────╯
// Command sanctum is Sanctum's HTTP server.
//
// Two run modes, selected at process start:
//
//	sanctum                # run the HTTP server. Boots LOCKED (D-4); a human
//	                       # unlocks via the web UI. SIGTERM re-seals cleanly.
//
//	sanctum -healthcheck   # short-lived: probe /healthz on the local port
//	                       # and exit 0 / 1. This is what the container's
//	                       # HEALTHCHECK invokes — the distroless image has
//	                       # no shell or curl, so a Go-side probe is what
//	                       # the compose file has always been calling.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/herbiewalker/sanctum/internal/config"
	"github.com/herbiewalker/sanctum/internal/httpapi"
	"github.com/herbiewalker/sanctum/internal/notify"
	"github.com/herbiewalker/sanctum/internal/retention"
	"github.com/herbiewalker/sanctum/internal/scheduler"
	"github.com/herbiewalker/sanctum/internal/updatecheck"
	"github.com/herbiewalker/sanctum/internal/vault"
)

// version is stamped at build time (-ldflags "-X main.version=..."); the
// Dockerfile passes the release tag. "dev" means an unreleased local build.
var version = "dev"

func main() {
	var (
		healthcheck = flag.Bool("healthcheck", false, "probe /healthz on the local port and exit")
		notifyTest  = flag.Bool("notify-test", false, "send one test notification through the configured channels and exit")
	)
	flag.Parse()

	if *notifyTest {
		os.Exit(runNotifyTest())
	}

	if *healthcheck {
		os.Exit(runHealthcheck())
	}

	if err := run(); err != nil {
		slog.Error("fatal", "err", err.Error())
		os.Exit(1)
	}
}

func run() error {
	// Structured logs to stdout (12-Factor XI). Content-safety rules from
	// N15 are enforced by every package that logs; the JSON handler here
	// just provides the transport.
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	cfg, err := config.Load()
	if err != nil {
		return err
	}

	v, err := vault.New(vault.Paths{
		VaultDir:            cfg.VaultDir,
		TmpDir:              cfg.TmpDir,
		InboxDir:            cfg.InboxDir,
		AllowNonTmpfsTmpDir: cfg.AllowNonTmpfsTmpDir,
	}, vault.Options{
		Now:    time.Now,
		Logger: logger,
	})
	if err != nil {
		return fmt.Errorf("vault: %w", err)
	}

	// The update checker needs the notifier, which is built below; the UI reads
	// it through this closure once it exists.
	var checker *updatecheck.Checker

	api, err := httpapi.New(httpapi.Config{
		Vault:         httpapi.Wrap(v),
		Logger:        logger,
		Now:           time.Now,
		Version:       version,
		StalenessDays: cfg.StalenessDays,
		LockedSince: func() int64 {
			st, err := v.State()
			if err != nil {
				return 0
			}
			return st.LockedSince
		},
		UpdateInfo: func() httpapi.UpdateInfo {
			if checker == nil {
				return httpapi.UpdateInfo{}
			}
			i := checker.Latest()
			return httpapi.UpdateInfo{Newer: i.Newer, Latest: i.Latest, URL: i.URL}
		},
	})
	if err != nil {
		return err
	}

	srv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           api.Routes(),
		ReadHeaderTimeout: 10 * time.Second,
		// Upload handler streams a large body; keep ReadTimeout generous
		// enough for a 34 MB file on a slow LAN.
		ReadTimeout:  10 * time.Minute,
		WriteTimeout: 10 * time.Minute,
		IdleTimeout:  60 * time.Second,
	}

	// Signal context BEFORE the listener so a SIGTERM during startup is
	// honoured rather than racing.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Notifier: FileDropNotifier if a drop dir was configured (D-18), otherwise
	// a NullNotifier so the scheduler runs quietly.
	notifier, err := buildNotifier(cfg, logger)
	if err != nil {
		return err
	}

	// Opt-in, read-only release lookup (ADR D-19). Reports only; it never
	// downloads or applies anything.
	if cfg.UpdateCheck {
		checker = updatecheck.New(updatecheck.Options{
			Current: version, Notifier: notifier, Now: time.Now, Logger: logger,
		})
		go checker.Run(ctx, time.Duration(cfg.UpdateCheckEveryHours)*time.Hour)
		logger.Info("update check enabled", "every_hours", cfg.UpdateCheckEveryHours)
	}

	// Scheduler: verify + retention + staleness / locked-since alert.
	sched, err := scheduler.New(scheduler.Config{
		VerifyEvery:    time.Duration(cfg.VerifyEveryHours) * time.Hour,
		RetentionEvery: time.Duration(cfg.RetentionEveryHours) * time.Hour,
		AlertEvery:     time.Duration(cfg.AlertEveryMinutes) * time.Minute,
		Retention: retention.Policy{
			KeepMin: cfg.RetentionKeepMin,
			MaxAge:  time.Duration(cfg.RetentionMaxAgeDays) * 24 * time.Hour,
		},
		StalenessDefault:    time.Duration(cfg.StalenessDays) * 24 * time.Hour,
		LockedAlertAfter:    time.Duration(cfg.LockedAlertAfterHours * float64(time.Hour)),
		LockedAlertDebounce: time.Duration(cfg.LockedAlertDebounceHours * float64(time.Hour)),
	}, scheduler.Options{
		Vault: v, Notifier: notifier, Now: time.Now, Logger: logger,
	})
	if err != nil {
		return fmt.Errorf("scheduler: %w", err)
	}
	go sched.Run(ctx)

	errCh := make(chan error, 1)
	go func() {
		logger.Info("sanctum listening",
			"version", version,
			"addr", cfg.Addr, "vault_dir", cfg.VaultDir, "state", "locked",
			"unlock_url", unlockURL(cfg.Addr))
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		logger.Info("shutdown signal received")
	}

	// N11: graceful shutdown. Stop accepting new connections, drain, then
	// call vault.Close() — which Locks if still unlocked (re-seals + zeroes
	// the runtime key). Order matters: if we Lock first and an in-flight
	// request needed the index, it would blow up mid-response.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownGrace)
	defer cancel()

	shutdownErr := srv.Shutdown(shutdownCtx)
	closeErr := v.Close()
	logger.Info("shutdown complete",
		"http_err", errOrNil(shutdownErr),
		"vault_err", errOrNil(closeErr))
	if shutdownErr != nil {
		return shutdownErr
	}
	return closeErr
}

// runHealthcheck performs a single GET on /healthz. Meant to be called from
// the container's HEALTHCHECK. Exits 0 if the server returns 200.
func runHealthcheck() int {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintln(os.Stderr, "healthcheck: config:", err)
		return 1
	}
	// Determine the port from cfg.Addr; healthcheck always talks to
	// localhost, even when the listener bound to a specific IP.
	port := "8080"
	if i := strings.LastIndexByte(cfg.Addr, ':'); i >= 0 && i < len(cfg.Addr)-1 {
		port = cfg.Addr[i+1:]
	}
	url := "http://127.0.0.1:" + port + "/healthz"

	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		fmt.Fprintln(os.Stderr, "healthcheck:", err)
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		fmt.Fprintln(os.Stderr, "healthcheck: status", resp.StatusCode)
		return 1
	}
	return 0
}

// unlockURL builds a friendly URL to show in the startup log line, so an
// operator can click straight to the unlock page. Best-effort: strips any
// bind-IP that is not a real host.
func unlockURL(addr string) string {
	host, port, ok := strings.Cut(addr, ":")
	if !ok {
		return "http://localhost:8080/"
	}
	if host == "" || host == "0.0.0.0" {
		host = "localhost"
	}
	return fmt.Sprintf("http://%s:%s/", host, port)
}

func errOrNil(err error) any {
	if err == nil {
		return nil
	}
	return err.Error()
}

// keep filepath imported (referenced by go vet in some builds); harmless.
var _ = filepath.Base

// ⏣ HW ⏣ · code · tools · homelab · ⏣ HW ⏣

// buildNotifier assembles the configured channels (ADR D-20): any URL
// channels (ntfy / Discord / Slack / webhook) plus, optionally, the D-18 drop
// directory for an Unraid host script. With nothing configured it returns a
// NullNotifier so the scheduler runs quietly.
func buildNotifier(cfg config.Config, logger *slog.Logger) (notify.Notifier, error) {
	var channels []notify.Notifier
	if cfg.NotifyURL != "" {
		urls, err := notify.ParseURLs(cfg.NotifyURL)
		if err != nil {
			// The error text never contains the URL (it is a credential).
			return nil, fmt.Errorf("SANCTUM_NOTIFY_URL: %w", err)
		}
		for _, u := range urls {
			channels = append(channels, u)
			logger.Info("notification channel", "channel", u.Describe())
		}
	}
	if cfg.NotifyDir != "" {
		fd, err := notify.NewFileDropNotifier(cfg.NotifyDir, time.Now)
		if err != nil {
			return nil, fmt.Errorf("notify: %w", err)
		}
		channels = append(channels, fd)
		logger.Info("notify drop directory", "path", fd.Dir())
	}
	switch len(channels) {
	case 0:
		logger.Warn("no notification channel configured; alerts are only visible in the web UI and logs. Set SANCTUM_NOTIFY_URL to be told when something needs attention")
		return notify.NullNotifier{}, nil
	case 1:
		return channels[0], nil
	}
	return notify.Multi{Channels: channels}, nil
}

// runNotifyTest sends one test notification through the configured channels
// and exits 0 on delivery. `docker exec sanctum /usr/local/bin/sanctum -notify-test`
func runNotifyTest() int {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintln(os.Stderr, "notify-test: config:", err)
		return 1
	}
	if cfg.NotifyURL == "" && cfg.NotifyDir == "" {
		fmt.Fprintln(os.Stderr, "notify-test: no channel configured (set SANCTUM_NOTIFY_URL)")
		return 1
	}
	n, err := buildNotifier(cfg, logger)
	if err != nil {
		fmt.Fprintln(os.Stderr, "notify-test:", err)
		return 1
	}
	if err := n.Notify(notify.Intent{
		At: time.Now().Unix(), Severity: notify.SeverityNormal, Kind: notify.KindTest,
		Subject: "Sanctum: test notification",
		Body:    "If you can read this, Sanctum can reach you.",
	}); err != nil {
		fmt.Fprintln(os.Stderr, "notify-test: delivery failed:", err)
		return 1
	}
	fmt.Println("notify-test: delivered")
	return 0
}
