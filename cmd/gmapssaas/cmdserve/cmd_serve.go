package cmdserve

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	httpSwagger "github.com/swaggo/http-swagger/v2"
	"github.com/urfave/cli/v3"

	"github.com/Tony27Alarcon/herramienta-de-ventas-interna/admin"
	adminpostgres "github.com/Tony27Alarcon/herramienta-de-ventas-interna/admin/postgres"
	"github.com/Tony27Alarcon/herramienta-de-ventas-interna/api"
	_ "github.com/Tony27Alarcon/herramienta-de-ventas-interna/api/docs" // registers swagger docs
	apipostgres "github.com/Tony27Alarcon/herramienta-de-ventas-interna/api/postgres"
	"github.com/Tony27Alarcon/herramienta-de-ventas-interna/cryptoext"
	"github.com/Tony27Alarcon/herramienta-de-ventas-interna/env"
	"github.com/Tony27Alarcon/herramienta-de-ventas-interna/httpext"
	"github.com/Tony27Alarcon/herramienta-de-ventas-interna/log"
	"github.com/Tony27Alarcon/herramienta-de-ventas-interna/migrations"
	"github.com/Tony27Alarcon/herramienta-de-ventas-interna/postgres"
	ratelimitpostgres "github.com/Tony27Alarcon/herramienta-de-ventas-interna/ratelimit/postgres"
	"github.com/Tony27Alarcon/herramienta-de-ventas-interna/rqueue"
	saas "github.com/Tony27Alarcon/herramienta-de-ventas-interna/saas"
)

// swappableHandler is a thread-safe http.Handler that allows replacing the
// underlying handler at runtime (e.g., swapping from an early health-only
// handler to the full application router once initialization is complete).
type swappableHandler struct {
	mu      sync.RWMutex
	handler http.Handler
}

func (s *swappableHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	h := s.handler
	s.mu.RUnlock()
	h.ServeHTTP(w, r)
}

func (s *swappableHandler) swap(h http.Handler) {
	s.mu.Lock()
	s.handler = h
	s.mu.Unlock()
}

var Command = &cli.Command{
	Name:  "serve",
	Usage: "Start the API server",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:    "addr",
			Usage:   "Server listen address",
			Value:   ":8080",
			Sources: cli.EnvVars("PORT", saas.EnvAddr),
		},
		&cli.StringFlag{
			Name:     "database-url",
			Usage:    "PostgreSQL connection string (e.g. postgresql://...@db.[ref].supabase.co:5432/postgres?sslmode=require)",
			Sources:  cli.EnvVars(saas.EnvDatabaseURL),
			Required: true,
		},
		&cli.IntFlag{
			Name:    "db-max-conns",
			Usage:   "Maximum database connections",
			Value:   10,
			Sources: cli.EnvVars(saas.EnvDBMaxConns),
		},
		&cli.IntFlag{
			Name:    "db-min-conns",
			Usage:   "Minimum database connections",
			Value:   2,
			Sources: cli.EnvVars(saas.EnvDBMinConns),
		},
		&cli.DurationFlag{
			Name:    "db-max-conn-lifetime",
			Usage:   "Maximum connection lifetime",
			Value:   time.Hour,
			Sources: cli.EnvVars(saas.EnvDBMaxConnLifetime),
		},
		&cli.DurationFlag{
			Name:    "db-max-conn-idle-time",
			Usage:   "Maximum connection idle time",
			Value:   30 * time.Minute,
			Sources: cli.EnvVars(saas.EnvDBMaxConnIdleTime),
		},
		&cli.StringFlag{
			Name:     "encryption-key",
			Usage:    "Hex-encoded 32-byte encryption key for sensitive data. Generate with: openssl rand -hex 32",
			Sources:  cli.EnvVars(saas.EnvEncryptionKey),
			Required: true,
		},
	},
	Action: func(ctx context.Context, cmd *cli.Command) error {
		addr := cmd.String("addr")
		if addr != "" && !strings.Contains(addr, ":") {
			addr = ":" + addr
		}
		dsn := cmd.String("database-url")

		// Start an early HTTP server so Railway's health check passes during
		// initialization. The handler is swapped to the full router once ready.
		dispatch := &swappableHandler{
			handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/health" {
					w.WriteHeader(http.StatusOK)
					return
				}
				http.Error(w, "service initializing", http.StatusServiceUnavailable)
			}),
		}

		srv, err := httpext.New(dispatch, httpext.WithAddr(addr))
		if err != nil {
			return err
		}

		srvErrCh := make(chan error, 1)
		go func() {
			log.Info("starting server", "addr", addr)
			srvErrCh <- srv.Run(ctx)
		}()

		// Run database migrations
		if n, err := migrations.RunWithDSN(dsn); err != nil {
			return fmt.Errorf("failed to run migrations: %w", err)
		} else if n > 0 {
			log.Info("database migrations applied", "count", n)
		}

		// Connect to database
		dbPool, err := postgres.Connect(ctx, dsn,
			postgres.WithMaxConns(int32(cmd.Int("db-max-conns"))),
			postgres.WithMinConns(int32(cmd.Int("db-min-conns"))),
			postgres.WithMaxConnLifetime(cmd.Duration("db-max-conn-lifetime")),
			postgres.WithMaxConnIdleTime(cmd.Duration("db-max-conn-idle-time")),
		)
		if err != nil {
			return err
		}
		defer dbPool.Close()

		// Parse and validate encryption key
		encKeyHex := cmd.String("encryption-key")
		if encKeyHex == "0398d4cad290e145cb8242bb74e045264564d384d33ada80ff7702e460e6956c" {
			return fmt.Errorf("ENCRYPTION_KEY must not be the default value. Generate one with: openssl rand -hex 32")
		}

		encryptionKey, err := cryptoext.ParseEncryptionKey(encKeyHex)
		if err != nil {
			return fmt.Errorf("invalid ENCRYPTION_KEY (must be 64 hex chars / 32 bytes): %w. Generate one with: openssl rand -hex 32", err)
		}

		env.LogUnsetEnvs(saas.EnvDatabaseURL, saas.EnvEncryptionKey)

		// Create stores
		adminStore := adminpostgres.NewWithPool(dbPool, encryptionKey)
		apiStore := apipostgres.New(dbPool)

		// Store database URL in config (encrypted)
		dsnConfig := &admin.AppConfig{
			Key:   "database_url",
			Value: dsn,
		}
		if err = adminStore.SetConfig(ctx, dsnConfig, true); err != nil {
			return err
		}

		// Create River queue client (processes maintenance queue for worker provisioning)
		rqueueClient, err := rqueue.NewClient(dbPool, encryptionKey)
		if err != nil {
			return err
		}

		if err = rqueueClient.Start(ctx); err != nil {
			return err
		}

		riverUIHandler, err := rqueue.CreateRiverUIHandler(ctx, rqueueClient)
		if err != nil {
			return err
		}

		if err = riverUIHandler.Start(ctx); err != nil {
			return err
		}

		// Create rate limiter
		rateLimiter := ratelimitpostgres.New(dbPool)

		// Create AppStates
		adminState, err := admin.NewAppState(adminStore, rateLimiter, encryptionKey)
		if err != nil {
			return err
		}

		adminState.RQueueClient = rqueueClient

		apiState := api.NewAppState(rqueueClient, apiStore)

		// Setup full application router
		mainRouter := chi.NewRouter()
		mainRouter.Use(middleware.Recoverer)

		// Setup admin routes
		admin.Routes(mainRouter, adminState, riverUIHandler)

		// Setup API routes (in a group so middleware can be added)
		mainRouter.Group(func(r chi.Router) {
			api.Routes(r, apiState)
		})

		// Health check
		mainRouter.Get("/health", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		// Swagger UI
		mainRouter.Get("/swagger/*", httpSwagger.Handler(
			httpSwagger.URL("/swagger/doc.json"),
		))

		// Swap early handler for full application router
		dispatch.swap(mainRouter)
		log.Info("server ready")

		return <-srvErrCh
	},
}
