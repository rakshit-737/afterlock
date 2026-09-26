// Command afterlock-collector gathers metadata-only Kubernetes evidence and
// writes an afterlock.replay/1 bundle.
//
// It is read-only against the cluster (list/watch only), ingests audit events
// from a log file and/or the webhook audit backend, spools them to a bounded
// local file, and records every observation gap explicitly.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/metadata"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/rakshit-737/afterlock/services/collector/internal/audit"
	"github.com/rakshit-737/afterlock/services/collector/internal/bundle"
	"github.com/rakshit-737/afterlock/services/collector/internal/inventory"
	"github.com/rakshit-737/afterlock/services/collector/internal/redact"
	"github.com/rakshit-737/afterlock/services/collector/internal/spool"
)

type config struct {
	kubeconfig, clusterID, sourceID, caseID, casePath, out, spoolPath string
	spoolMaxBytes                                                     int64
	spoolMaxRecords                                                   int
	auditLog, webhookListen, webhookTokenFile, tlsCert, tlsKey        string
	insecureHTTP, noCluster, secretMetadata                           bool
	duration, syncTimeout                                             time.Duration
}

func main() {
	var c config
	flag.StringVar(&c.kubeconfig, "kubeconfig", "", "kubeconfig path (default: in-cluster config)")
	flag.BoolVar(&c.noCluster, "no-cluster", false, "do not contact a cluster; inventory is recorded as unsynced (gap records)")
	flag.StringVar(&c.clusterID, "cluster-id", "", "cluster identifier written to every record (required)")
	flag.StringVar(&c.sourceID, "source-id", "afterlock-collector", "evidence source identifier")
	flag.StringVar(&c.caseID, "case-id", "", "bundle case id (default: cluster id)")
	flag.StringVar(&c.casePath, "case", "", "analyst-authored case.json template (default: an empty case)")
	flag.StringVar(&c.out, "out", "", "output bundle directory (required)")
	flag.StringVar(&c.spoolPath, "spool", "afterlock-spool.jsonl", "local spool file (reused across restarts)")
	flag.Int64Var(&c.spoolMaxBytes, "spool-max-bytes", 64<<20, "spool byte limit")
	flag.IntVar(&c.spoolMaxRecords, "spool-max-records", 200_000, "spool record limit")
	flag.StringVar(&c.auditLog, "audit-log", "", "audit log file (JSON lines, audit.k8s.io/v1) to ingest")
	flag.StringVar(&c.webhookListen, "webhook-listen", "", "address for the audit webhook backend receiver (e.g. :8443)")
	flag.StringVar(&c.webhookTokenFile, "webhook-token-file", "", "file holding the bearer token the audit webhook must present")
	flag.StringVar(&c.tlsCert, "tls-cert", "", "TLS certificate for the webhook receiver")
	flag.StringVar(&c.tlsKey, "tls-key", "", "TLS key for the webhook receiver")
	flag.BoolVar(&c.insecureHTTP, "insecure-http-loopback", false, "serve the webhook over plain HTTP; only permitted on a loopback address")
	flag.BoolVar(&c.secretMetadata, "secret-metadata", false, "watch Secret metadata (PartialObjectMetadata); requires the optional secret-metadata ClusterRole")
	flag.DurationVar(&c.duration, "duration", 0, "how long to collect before writing the bundle (0: until SIGINT/SIGTERM, or immediately if only --audit-log is given)")
	flag.DurationVar(&c.syncTimeout, "sync-timeout", 60*time.Second, "how long to wait for the initial inventory lists")
	flag.Parse()
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if err := run(c, log); err != nil {
		log.Error("collector failed", "error", redact.String(err.Error()))
		os.Exit(1)
	}
}

func run(c config, log *slog.Logger) error {
	if c.clusterID == "" || c.out == "" {
		return errors.New("--cluster-id and --out are required")
	}
	if c.caseID == "" {
		c.caseID = c.clusterID
	}
	var caseDoc map[string]any
	if c.casePath != "" {
		raw, err := os.ReadFile(c.casePath)
		if err != nil {
			return err
		}
		if err := json.Unmarshal(raw, &caseDoc); err != nil || caseDoc == nil {
			return fmt.Errorf("%s: case template must be a JSON object", c.casePath)
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	sp, err := spool.Open(spool.Options{
		Path: c.spoolPath, MaxBytes: c.spoolMaxBytes, MaxRecords: c.spoolMaxRecords,
		SourceID: c.sourceID, ClusterID: c.clusterID,
		OnOverflow: func(dropped int64) {
			log.Error("ALARM: evidence spool overflow; new evidence is being dropped and recorded as a gap", "dropped", dropped)
		},
	})
	if err != nil {
		return err
	}
	defer sp.Close()
	in := audit.NewIngester(sp)
	store := inventory.NewStore()
	gap := func(kind, reason string) {
		if err := sp.Gap(kind, reason); err != nil {
			log.Error("could not record gap", "kind", kind, "error", redact.String(err.Error()))
		}
	}

	var coll *inventory.Collector
	collCtx, cancelColl := context.WithCancel(ctx)
	defer cancelColl()
	done := make(chan struct{})
	if c.noCluster {
		// No client is ever called; the collector is built only so Kinds()
		// reports every kind as unsynced (recorded as gaps in the bundle).
		var md metadata.Interface
		if c.secretMetadata {
			md = metadataPlaceholder{}
		}
		coll = inventory.New(nil, md, store, gap)
		close(done)
	} else {
		cfg, err := restConfig(c.kubeconfig)
		if err != nil {
			return err
		}
		cfg.UserAgent = "afterlock-collector"
		cs, err := kubernetes.NewForConfig(cfg)
		if err != nil {
			return err
		}
		var md metadata.Interface
		if c.secretMetadata {
			if md, err = metadata.NewForConfig(cfg); err != nil {
				return err
			}
		}
		coll = inventory.New(cs, md, store, gap)
		go func() { coll.Run(collCtx); close(done) }()
		waitSynced(ctx, store, coll.Kinds(), c.syncTimeout)
	}

	if c.auditLog != "" {
		f, err := os.Open(c.auditLog)
		if err != nil {
			return err
		}
		err = in.IngestLog(f, "audit-log")
		_ = f.Close()
		if err != nil {
			return err
		}
	}

	var srv *http.Server
	if c.webhookListen != "" {
		srv, err = serve(c, in, sp, coll, log)
		if err != nil {
			return err
		}
	}

	switch {
	case c.duration > 0:
		select {
		case <-ctx.Done():
		case <-time.After(c.duration):
		}
	case c.webhookListen != "" || (!c.noCluster && c.auditLog == ""):
		<-ctx.Done()
	}
	if srv != nil {
		sh, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		_ = srv.Shutdown(sh)
		cancel()
	}
	cancelColl()
	<-done

	snap := store.Snapshot(coll.Kinds())
	if err := bundle.Write(bundle.Options{
		Dir: c.out, CaseID: c.caseID, ClusterID: c.clusterID, SourceID: c.sourceID,
		Case: caseDoc, Now: time.Now(), SecretMetadata: c.secretMetadata,
	}, sp.Records(), snap, store); err != nil {
		return err
	}
	st := sp.Stats()
	log.Info("bundle written", "dir", c.out, "records", st.Records, "dropped", st.Dropped,
		"audit_accepted", in.Counters.Accepted.Load(), "audit_duplicates", in.Counters.Duplicates.Load(),
		"audit_bodies_dropped", in.Counters.BodiesDropped.Load(), "redactions", redact.Redactions())
	return nil
}

// metadataPlaceholder only exists so --no-cluster --secret-metadata lists the
// secrets kind as unsynced; it is never called.
type metadataPlaceholder struct{ metadata.Interface }

func restConfig(kubeconfig string) (*rest.Config, error) {
	if kubeconfig != "" {
		return clientcmd.BuildConfigFromFlags("", kubeconfig)
	}
	return rest.InClusterConfig()
}

func waitSynced(ctx context.Context, store *inventory.Store, kinds []string, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) && ctx.Err() == nil {
		all := true
		for _, k := range kinds {
			all = all && store.Synced(k)
		}
		if all {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func serve(c config, in *audit.Ingester, sp *spool.Spool, coll *inventory.Collector, log *slog.Logger) (*http.Server, error) {
	raw, err := os.ReadFile(c.webhookTokenFile)
	if err != nil {
		return nil, fmt.Errorf("--webhook-token-file: %w", err)
	}
	h, err := audit.NewWebhookHandler(in, string(raw))
	if err != nil {
		return nil, err
	}
	tlsOn := c.tlsCert != "" && c.tlsKey != ""
	if !tlsOn {
		host, _, err := net.SplitHostPort(c.webhookListen)
		ip := net.ParseIP(host)
		if !c.insecureHTTP || err != nil || ip == nil || !ip.IsLoopback() {
			return nil, errors.New("the webhook receiver requires --tls-cert/--tls-key (plain HTTP is only allowed with --insecure-http-loopback on a loopback address)")
		}
	}
	mux := http.NewServeMux()
	mux.Handle("/v1/audit", h)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok\n")) })
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		st := sp.Stats()
		var b strings.Builder
		fmt.Fprintf(&b, "afterlock_collector_spool_records %d\n", st.Records)
		fmt.Fprintf(&b, "afterlock_collector_spool_bytes %d\n", st.Bytes)
		fmt.Fprintf(&b, "afterlock_collector_spool_dropped_total %d\n", st.Dropped)
		fmt.Fprintf(&b, "afterlock_collector_spool_overflow %d\n", boolInt(st.Overflowed))
		fmt.Fprintf(&b, "afterlock_collector_audit_accepted_total %d\n", in.Counters.Accepted.Load())
		fmt.Fprintf(&b, "afterlock_collector_audit_duplicates_total %d\n", in.Counters.Duplicates.Load())
		fmt.Fprintf(&b, "afterlock_collector_audit_malformed_total %d\n", in.Counters.Malformed.Load())
		fmt.Fprintf(&b, "afterlock_collector_audit_bodies_dropped_total %d\n", in.Counters.BodiesDropped.Load())
		fmt.Fprintf(&b, "afterlock_collector_redactions_total %d\n", redact.Redactions())
		for k, v := range coll.Restarts() {
			fmt.Fprintf(&b, "afterlock_collector_watch_restarts_total{kind=%q} %d\n", k, v)
		}
		_, _ = w.Write([]byte(b.String()))
	})
	srv := &http.Server{Addr: c.webhookListen, Handler: mux, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second}
	go func() {
		var err error
		if tlsOn {
			err = srv.ListenAndServeTLS(c.tlsCert, c.tlsKey)
		} else {
			err = srv.ListenAndServe()
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("webhook receiver stopped", "error", redact.String(err.Error()))
		}
	}()
	return srv, nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
