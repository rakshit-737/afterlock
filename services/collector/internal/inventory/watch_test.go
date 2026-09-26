package inventory

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

type gapLog struct {
	mu   sync.Mutex
	gaps []string
}

func (g *gapLog) add(kind, reason string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.gaps = append(g.gaps, kind+": "+reason)
}

func (g *gapLog) has(kind, sub string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, x := range g.gaps {
		if strings.HasPrefix(x, kind+":") && strings.Contains(x, sub) {
			return true
		}
	}
	return false
}

func pod(name, uid string) *corev1.Pod {
	return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "demo", Name: name, UID: types.UID(uid), ResourceVersion: "rv-" + uid},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Env: []corev1.EnvVar{{Name: "T", Value: "AFTERLOCK-CANARY-env"}}}}}}
}

// harness replaces the pods watch with controllable fake watchers.
func harness(t *testing.T) (*Collector, *Store, *gapLog, chan *watch.FakeWatcher, context.CancelFunc, chan struct{}) {
	t.Helper()
	cs := fake.NewSimpleClientset(pod("a", "uid-a"))
	watchers := make(chan *watch.FakeWatcher, 8)
	cs.PrependWatchReactor("pods", func(k8stesting.Action) (bool, watch.Interface, error) {
		w := watch.NewFakeWithChanSize(8, false)
		watchers <- w
		return true, w, nil
	})
	store := NewStore()
	gl := &gapLog{}
	c := New(cs, nil, store, gl.add)
	c.Backoff = time.Millisecond
	c.specs = c.specs[:1] // pods only
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { c.Run(ctx); close(done) }()
	return c, store, gl, watchers, cancel, done
}

func next(t *testing.T, ch chan *watch.FakeWatcher) *watch.FakeWatcher {
	t.Helper()
	select {
	case w := <-ch:
		return w
	case <-time.After(5 * time.Second):
		t.Fatal("no watch established")
		return nil
	}
}

func eventually(t *testing.T, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for " + what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func podNames(s *Store) string {
	snap := s.Snapshot([]string{KindPod})
	var names []string
	for _, p := range snap.Inventory["pods"].([]any) {
		names = append(names, p.(map[string]any)["name"].(string))
	}
	return strings.Join(names, ",")
}

func TestWatchEventsUpdateInventory(t *testing.T) {
	_, store, gl, ws, cancel, done := harness(t)
	w := next(t, ws)
	w.Add(pod("b", "uid-b"))
	w.Delete(pod("a", "uid-a"))
	eventually(t, func() bool { return podNames(store) == "b" }, "watch events applied")
	cancel()
	<-done
	if len(gl.gaps) != 0 {
		t.Fatalf("unexpected gaps: %v", gl.gaps)
	}
	if len(store.PodsNamed("demo", "a")) != 1 {
		t.Fatal("deleted pod missing from correlation history")
	}
}

func TestExpiredResourceVersionRecordsGapAndRelists(t *testing.T) {
	_, _, gl, ws, cancel, done := harness(t)
	w := next(t, ws)
	w.Error(&metav1.Status{Status: metav1.StatusFailure, Code: 410, Reason: metav1.StatusReasonExpired, Message: "too old resource version"})
	next(t, ws) // a new watch after the relist
	eventually(t, func() bool { return gl.has("resource-version-expired", "pods") && gl.has("relist", "pods") }, "expiry and relist gaps")
	cancel()
	<-done
}

func TestClosedWatchRecordsRestartGap(t *testing.T) {
	c, _, gl, ws, cancel, done := harness(t)
	w := next(t, ws)
	w.Stop()
	next(t, ws)
	eventually(t, func() bool { return gl.has("watch-restarted", "pods") }, "restart gap")
	cancel()
	<-done
	if c.Restarts()[KindPod] < 1 {
		t.Fatal("restart not counted")
	}
}

func TestListFailureRecordsGap(t *testing.T) {
	cs := fake.NewSimpleClientset()
	calls := 0
	cs.PrependReactor("list", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
		calls++
		if calls == 1 {
			return true, nil, &errStatus{}
		}
		return false, nil, nil
	})
	store := NewStore()
	gl := &gapLog{}
	c := New(cs, nil, store, gl.add)
	c.Backoff = time.Millisecond
	c.specs = c.specs[:1]
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { c.Run(ctx); close(done) }()
	eventually(t, func() bool { return store.Synced(KindPod) }, "sync after failure")
	cancel()
	<-done
	if !gl.has("list-failed", "pods") {
		t.Fatalf("gaps = %v", gl.gaps)
	}
}

type errStatus struct{}

func (errStatus) Error() string { return "boom" }

func TestConvertersRetainOnlyAllowlistedMetadata(t *testing.T) {
	_, item, ok := convertPod(pod("a", "uid-a"))
	if !ok {
		t.Fatal("pod not converted")
	}
	p := item.(Pod)
	if p.ServiceAccount != "default" || p.UID != "uid-a" {
		t.Fatalf("pod = %+v", p)
	}
	full := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "s", UID: "u"}, Data: map[string][]byte{"k": []byte("v")}}
	if _, _, ok := convertSecret(full); ok {
		t.Fatal("a full Secret object must be rejected by the metadata-only converter")
	}
}

func TestSecretVersionUsesOpaqueResourceVersionEquality(t *testing.T) {
	s := NewStore()
	sec := func(uid, rv string) Secret { return Secret{Named{"demo", "s", uid}, rv} }
	s.Upsert(KindSecret, "u1", sec("u1", "999"))
	s.Upsert(KindSecret, "u1", sec("u1", "999")) // resync, no change
	s.Upsert(KindSecret, "u1", sec("u1", "5"))   // "smaller" RV is still just different
	v := s.Snapshot(nil).Inventory["secrets"].([]any)[0].(map[string]any)["version"]
	if v != 2 {
		t.Fatalf("version = %v, want 2", v)
	}
	s.Delete(KindSecret, "u1")
	s.Upsert(KindSecret, "u2", sec("u2", "1")) // same name, new UID: a new object
	v = s.Snapshot(nil).Inventory["secrets"].([]any)[0].(map[string]any)["version"]
	if v != 1 {
		t.Fatalf("recreated secret version = %v, want 1", v)
	}
}
