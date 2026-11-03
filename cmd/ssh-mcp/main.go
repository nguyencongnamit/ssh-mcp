// Command ssh-mcp is the central server and its admin CLI.
//
//	ssh-mcp serve        -config ssh-mcp.yaml
//	ssh-mcp ca init      -key /etc/ssh-mcp/ca_key
//	ssh-mcp ca pubkey    -config ssh-mcp.yaml
//	ssh-mcp token create -config ssh-mcp.yaml -name triage-bot -owner ops -ttl 720h
//	ssh-mcp token list   -config ssh-mcp.yaml
//	ssh-mcp token revoke -config ssh-mcp.yaml -name triage-bot
//	ssh-mcp kill         -config ssh-mcp.yaml (-identity bot:triage-bot | -all) -reason "..."
//	ssh-mcp unkill       -config ssh-mcp.yaml (-identity bot:triage-bot | -all)
//	ssh-mcp audit keygen -out /etc/ssh-mcp/audit.key
//	ssh-mcp audit verify -config ssh-mcp.yaml
//	ssh-mcp audit tail   -config ssh-mcp.yaml -n 50
//	ssh-mcp policy check -config ssh-mcp.yaml
//	ssh-mcp console passwd   (reads a password on stdin, prints a bcrypt hash)
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"os/user"
	"strings"
	"syscall"
	"time"
	_ "time/tzdata" // console.timezone works in minimal containers

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/oauthex"

	"github.com/nguyencongnamit/ssh-mcp/internal/alerts"
	"github.com/nguyencongnamit/ssh-mcp/internal/authn"
	"github.com/nguyencongnamit/ssh-mcp/internal/ca"
	"github.com/nguyencongnamit/ssh-mcp/internal/config"
	"github.com/nguyencongnamit/ssh-mcp/internal/console"
	"github.com/nguyencongnamit/ssh-mcp/internal/identity"
	"github.com/nguyencongnamit/ssh-mcp/internal/inventory"
	"github.com/nguyencongnamit/ssh-mcp/internal/live"
	"github.com/nguyencongnamit/ssh-mcp/internal/policy"
	"github.com/nguyencongnamit/ssh-mcp/internal/redact"
	"github.com/nguyencongnamit/ssh-mcp/internal/sandbox"
	"github.com/nguyencongnamit/ssh-mcp/internal/server"
	"github.com/nguyencongnamit/ssh-mcp/internal/store"
	"github.com/nguyencongnamit/ssh-mcp/internal/transport"
)

var version = "dev"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "ssh-mcp:", err)
		os.Exit(1)
	}
}

func usage() error {
	return errors.New("usage: ssh-mcp serve|ca init|ca pubkey|token create|token list|token revoke|kill|unkill|audit keygen|audit verify|audit tail|policy check|console passwd|version")
}

func run(args []string) error {
	if len(args) == 0 {
		return usage()
	}
	cmd, rest := args[0], args[1:]
	sub := ""
	if len(rest) > 0 && (cmd == "ca" || cmd == "token" || cmd == "audit" || cmd == "policy" || cmd == "console") {
		sub, rest = rest[0], rest[1:]
	}
	switch cmd + " " + sub {
	case "serve ":
		return serve(rest)
	case "version ":
		fmt.Println(version)
		return nil
	case "ca init":
		fs := flag.NewFlagSet("ca init", flag.ExitOnError)
		key := fs.String("key", "", "path for the new CA private key")
		fs.Parse(rest) //nolint:errcheck
		if *key == "" {
			return errors.New("-key is required")
		}
		pub, err := ca.GenerateFile(*key)
		if err != nil {
			return err
		}
		fmt.Print(pub)
		fmt.Fprintln(os.Stderr, "CA key written. Put the public key above in /etc/ssh/ssh-mcp-ca.pub on each target.")
		return nil
	case "ca pubkey":
		cfg, err := loadConfig("ca pubkey", rest, nil)
		if err != nil {
			return err
		}
		c, err := cfg.LoadCA(context.Background())
		if err != nil {
			return err
		}
		fmt.Print(c.PublicKey())
		return nil
	case "token create":
		var name, owner string
		var ttl time.Duration
		cfg, err := loadConfig("token create", rest, func(fs *flag.FlagSet) {
			fs.StringVar(&name, "name", "", "token name (used in policy as who.token)")
			fs.StringVar(&owner, "owner", "", "person responsible for this bot")
			fs.DurationVar(&ttl, "ttl", 30*24*time.Hour, "lifetime (max 2160h)")
		})
		if err != nil {
			return err
		}
		if owner == "" {
			return errors.New("-owner is required")
		}
		return withStore(cfg, func(st *store.Store) error {
			tok, err := st.CreateToken(context.Background(), name, owner, ttl)
			if err != nil {
				return err
			}
			if err := cliAudit(st, "token_create", "bot:"+name, "owner "+owner+", ttl "+ttl.String()); err != nil {
				return err
			}
			fmt.Println(tok)
			fmt.Fprintln(os.Stderr, "Shown once. Store it in the bot's secret store; ssh-mcp keeps only a hash.")
			return nil
		})
	case "token list":
		cfg, err := loadConfig("token list", rest, nil)
		if err != nil {
			return err
		}
		return withStore(cfg, func(st *store.Store) error {
			ts, err := st.ListTokens(context.Background())
			if err != nil {
				return err
			}
			for _, t := range ts {
				fmt.Printf("%-24s owner=%-16s expires=%s revoked=%v\n", t.Name, t.Owner, t.Expires, t.Revoked)
			}
			return nil
		})
	case "token revoke":
		var name string
		cfg, err := loadConfig("token revoke", rest, func(fs *flag.FlagSet) { fs.StringVar(&name, "name", "", "token name") })
		if err != nil {
			return err
		}
		return withStore(cfg, func(st *store.Store) error {
			if err := st.RevokeToken(context.Background(), name); err != nil {
				return err
			}
			return cliAudit(st, "token_revoke", "bot:"+name, "")
		})
	case "kill ", "unkill ":
		var id, reason string
		var all bool
		cfg, err := loadConfig(cmd, rest, func(fs *flag.FlagSet) {
			fs.StringVar(&id, "identity", "", "identity key: bot:<token-name> or user:<entra-object-id>")
			fs.BoolVar(&all, "all", false, "every identity")
			fs.StringVar(&reason, "reason", "", "why (recorded)")
		})
		if err != nil {
			return err
		}
		if all == (id != "") {
			return errors.New("give exactly one of -identity or -all")
		}
		key := store.GlobalKill
		if !all {
			if key, err = identity.NormalizeKey(id); err != nil {
				return err
			}
		}
		return withStore(cfg, func(st *store.Store) error {
			if !all {
				if seen, _ := st.SeenIdentity(context.Background(), key); !seen {
					fmt.Fprintf(os.Stderr, "warning: %s has never appeared in the audit log; check for a typo\n", key)
				}
			}
			if cmd == "kill" {
				if reason == "" {
					return errors.New("-reason is required")
				}
				if err := st.Disable(context.Background(), key, reason); err != nil {
					return err
				}
				return cliAudit(st, "kill", key, reason)
			}
			if err := st.Enable(context.Background(), key); err != nil {
				return err
			}
			return cliAudit(st, "unkill", key, "")
		})
	case "audit keygen":
		fs := flag.NewFlagSet("audit keygen", flag.ExitOnError)
		out := fs.String("out", "", "path for the new audit HMAC key (keep it outside data_dir)")
		fs.Parse(rest) //nolint:errcheck
		if *out == "" {
			return errors.New("-out is required")
		}
		buf := make([]byte, 32)
		if _, err := rand.Read(buf); err != nil {
			return err
		}
		f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		if _, err := f.WriteString(hex.EncodeToString(buf) + "\n"); err != nil {
			f.Close()
			return err
		}
		return f.Close()
	case "audit verify":
		cfg, err := loadConfig("audit verify", rest, nil)
		if err != nil {
			return err
		}
		return withStore(cfg, func(st *store.Store) error {
			n, broken, err := st.Verify(context.Background())
			if err != nil {
				return err
			}
			if broken != 0 {
				return fmt.Errorf("audit chain BROKEN at record %d (%d records checked)", broken, n)
			}
			fmt.Printf("audit chain intact: %d records\n", n)
			return nil
		})
	case "audit tail":
		var n int
		cfg, err := loadConfig("audit tail", rest, func(fs *flag.FlagSet) { fs.IntVar(&n, "n", 50, "records") })
		if err != nil {
			return err
		}
		return withStore(cfg, func(st *store.Store) error {
			recs, err := st.Tail(context.Background(), n)
			if err != nil {
				return err
			}
			enc := json.NewEncoder(os.Stdout)
			for _, r := range recs {
				if err := enc.Encode(r); err != nil {
					return err
				}
			}
			return nil
		})
	case "console passwd":
		fmt.Fprint(os.Stderr, "Console password (min 12 chars), then Enter: ")
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && line == "" {
			return err
		}
		h, err := console.HashPassword(strings.TrimRight(line, "\r\n"))
		if err != nil {
			return err
		}
		fmt.Println(h)
		fmt.Fprintln(os.Stderr, "Put this in console.password_hash.")
		return nil
	case "policy check":
		cfg, err := loadConfig("policy check", rest, nil)
		if err != nil {
			return err
		}
		p, err := policy.Load(cfg.Policy, server.KnownTools)
		if err != nil {
			return err
		}
		fmt.Printf("policy ok: %d rules\n", len(p.Rules))
		return nil
	}
	return usage()
}

func loadConfig(name string, args []string, extra func(*flag.FlagSet)) (*config.Config, error) {
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	path := fs.String("config", "/etc/ssh-mcp/ssh-mcp.yaml", "config file")
	if extra != nil {
		extra(fs)
	}
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	return config.Load(*path)
}

func withStore(cfg *config.Config, fn func(*store.Store) error) error {
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return err
	}
	st, err := store.Open(cfg.DBPath())
	if err != nil {
		return err
	}
	defer st.Close()
	if err := applyAuditKey(cfg, st); err != nil {
		return err
	}
	return fn(st)
}

// cliAudit records an admin action taken from the command line, the same
// way the console records its own ("console:<user>").
func cliAudit(st *store.Store, tool, target, reason string) error {
	who := os.Getenv("SUDO_USER")
	if who == "" {
		if u, err := user.Current(); err == nil {
			who = u.Username
		}
	}
	_, err := st.Append(context.Background(), store.Record{
		Identity: "cli:" + who, Tool: tool, Args: target, Decision: "admin", Reason: reason,
	})
	return err
}

func applyAuditKey(cfg *config.Config, st *store.Store) error {
	if cfg.AuditKey == "" {
		return nil
	}
	fi, err := os.Stat(cfg.AuditKey)
	if err != nil {
		return fmt.Errorf("audit_key: %w", err)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("audit_key %s: permissions %o are too open (want 0600)", cfg.AuditKey, fi.Mode().Perm())
	}
	b, err := os.ReadFile(cfg.AuditKey)
	if err != nil {
		return err
	}
	key, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(key) < 32 {
		return errors.New("audit_key must hold at least 32 hex-encoded bytes (ssh-mcp audit keygen)")
	}
	st.SetAuditKey(key)
	return nil
}

func serve(args []string) error {
	cfg, err := loadConfig("serve", args, nil)
	if err != nil {
		return err
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return err
	}
	st, err := store.Open(cfg.DBPath())
	if err != nil {
		return err
	}
	defer st.Close()
	if err := applyAuditKey(cfg, st); err != nil {
		return err
	}
	if cfg.AuditKey == "" {
		log.Warn("audit_key not set: the audit chain is unkeyed and can be rebuilt by anyone who can write the database")
	}
	if n, broken, err := st.Verify(ctx); err != nil || broken != 0 {
		return fmt.Errorf("audit chain check failed at startup (broken at %d of %d): %v", broken, n, err)
	}

	pol, err := policy.Load(cfg.Policy, server.KnownTools)
	if err != nil {
		return err
	}
	authority, err := cfg.LoadCA(ctx)
	if err != nil {
		return err
	}
	pathsJSON, err := json.Marshal(pol.Paths)
	if err != nil {
		return err
	}
	authority.Paths = string(pathsJSON)
	if cfg.HelperPath != "" {
		authority.HelperPath = cfg.HelperPath
	}
	hostKeys, err := live.HostKeysFromFile(cfg.KnownHosts)
	if err != nil {
		return fmt.Errorf("known_hosts: %w", err)
	}

	var sources inventory.Multi
	if cfg.Inventory.Static != "" {
		s, err := inventory.LoadStatic(cfg.Inventory.Static)
		if err != nil {
			return err
		}
		sources = append(sources, s)
	}
	for _, e := range cfg.Inventory.EC2 {
		sources = append(sources, &inventory.EC2{Region: e.Region, Profile: e.Profile})
	}
	inv := &inventory.Cached{Src: sources, TTL: 2 * time.Minute}

	dialer := transport.Auto{}
	if cfg.Transport.SSM {
		dialer.SSM = &transport.SSM{}
	}
	if cfg.Transport.Direct {
		dialer.Direct = &transport.Direct{Timeout: 10 * time.Second}
	}

	polRef := policy.NewHolder(pol)
	reloader := &server.Reloader{Path: cfg.Policy, Holder: polRef, CA: authority, Store: st, Log: log}
	srv := &server.Server{
		Store:     st,
		PolicyRef: polRef,
		Inventory: inv,
		Live:      &live.Client{CA: authority, Dialer: dialer, HostKey: hostKeys, DirectSource: cfg.SourceAddress},
		Redactor:  redact.Default(),
		Log:       log,
		Version:   version,
	}
	if cfg.Sandbox.Enabled {
		if err := sandbox.CheckPrefixes(cfg.Sandbox.Prefixes, pol.Paths.Allow); err != nil {
			return err
		}
		m := &sandbox.Mirrors{
			Root: cfg.DataDir + "/mirrors", StateDir: cfg.DataDir + "/mirror-keys",
			Prefixes: cfg.Sandbox.Prefixes, KnownHosts: cfg.KnownHosts, CA: authority, Log: log,
			DirectSource: cfg.SourceAddress, IdleTimeout: 10 * time.Minute,
			Allowed: func(ctx context.Context) bool {
				off, _, err := st.IsDisabled(ctx, store.GlobalKill)
				return !off && err == nil
			},
			OnIssue: func(ctx context.Context, hostID string, serial uint64) {
				if _, err := st.Append(ctx, store.Record{
					Identity: "system:mirror", Host: hostID, Tool: "mirror_cert",
					Args: fmt.Sprintf(`{"serial":%d}`, serial), Decision: "issue",
				}); err != nil {
					log.Error("audit mirror certificate", "err", err)
				}
			},
		}
		defer m.Close()
		srv.Mirrors = m
		reloader.Mirrors = m
		reloader.SandboxPrefixes = cfg.Sandbox.Prefixes
		runner := sandbox.NewRunner(cfg.Sandbox.MaxConcurrent)
		if err := runner.DetectFeatures(); err != nil {
			return err
		}
		if !runner.SizeFlag {
			log.Warn("bwrap has no --size; sandbox /tmp is bounded only by the sandbox cgroup's memory.max")
		}
		if cfg.Sandbox.Cgroups != "off" {
			cg, err := sandbox.InitCgroups(128, 512<<20)
			switch {
			case err == nil:
				runner.Cgroups = cg
				log.Info("sandbox cgroups active", "pids_max", cg.PidsMax, "memory_max", cg.MemoryMax)
			case cfg.Sandbox.Cgroups == "required":
				return fmt.Errorf("sandbox cgroups: %w", err)
			default:
				log.Warn("sandbox cgroups unavailable; only rlimits, tmpfs size and the concurrency cap apply", "err", err)
			}
		}
		srv.Sandbox = runner
	}

	if cfg.Alerts.Enabled {
		w, err := alerts.New(cfg.Alerts, st, log)
		if err != nil {
			return fmt.Errorf("alerts: %w", err)
		}
		go w.Run(ctx)
		log.Info("alerts on", "sinks", len(w.Sinks))
	}

	// SIGHUP re-reads policy.yaml (systemctl reload ssh-mcp).
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-hup:
				_ = reloader.Reload(ctx) // logged and audited either way
			}
		}
	}()

	authr, err := authn.New(ctx, st, cfg.OIDC)
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	bearerOpts := &auth.RequireBearerTokenOptions{}
	if cfg.OIDC != nil && cfg.OIDC.Issuer != "" && cfg.PublicURL != "" {
		metaURL := cfg.PublicURL + "/.well-known/oauth-protected-resource"
		bearerOpts.ResourceMetadataURL = metaURL
		meta := &oauthex.ProtectedResourceMetadata{
			Resource:             cfg.PublicURL + "/mcp",
			AuthorizationServers: []string{cfg.OIDC.Issuer},
			ResourceName:         "ssh-mcp",
		}
		if cfg.OIDC.RequiredScope != "" {
			meta.ScopesSupported = []string{cfg.OIDC.RequiredScope}
		}
		mux.Handle("/.well-known/oauth-protected-resource", auth.ProtectedResourceMetadataHandler(meta))
	}
	mux.Handle("/mcp", srv.Handler(authr.Verify, bearerOpts))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok\n")) }) //nolint:errcheck

	hs := &http.Server{
		Addr:              cfg.Listen,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		hs.Shutdown(sctx) //nolint:errcheck
	}()
	if cfg.Console.Listen != "" {
		con := &console.Console{
			Store: st, PolicyRef: polRef, Inventory: inv, Version: version, Log: log,
			User: cfg.Console.User, PasswordHash: cfg.Console.PasswordHash, Tools: server.KnownTools,
		}
		if cfg.Console.Timezone != "" {
			loc, err := time.LoadLocation(cfg.Console.Timezone)
			if err != nil {
				return fmt.Errorf("console.timezone: %w", err)
			}
			con.Loc = loc
		}
		ch, err := con.Handler()
		if err != nil {
			return err
		}
		cs := &http.Server{Addr: cfg.Console.Listen, Handler: ch, ReadHeaderTimeout: 10 * time.Second}
		go func() {
			<-ctx.Done()
			cs.Close() //nolint:errcheck
		}()
		go func() {
			log.Info("console listening", "addr", cfg.Console.Listen)
			if err := cs.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Error("console stopped", "err", err)
			}
		}()
	}
	log.Info("ssh-mcp listening", "addr", cfg.Listen, "tls", cfg.TLS.CertFile != "", "oidc", cfg.OIDC != nil && cfg.OIDC.Issuer != "", "sandbox", cfg.Sandbox.Enabled)
	if cfg.TLS.CertFile != "" {
		err = hs.ListenAndServeTLS(cfg.TLS.CertFile, cfg.TLS.KeyFile)
	} else {
		log.Warn("serving plain HTTP: put ssh-mcp behind TLS (ALB or tls config) outside the test bed")
		err = hs.ListenAndServe()
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
