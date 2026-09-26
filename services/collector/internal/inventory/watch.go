package inventory

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/metadata"

	"github.com/rakshit-737/afterlock/services/collector/internal/redact"
)

// GapFunc records an explicit observation gap (kind, human-readable reason).
type GapFunc func(kind, reason string)

// kindSpec is the read-only access used for one resource kind: list and
// watch only. No other verb is ever issued.
type kindSpec struct {
	kind    string
	list    func(ctx context.Context, opts metav1.ListOptions) ([]runtime.Object, string, error)
	watch   func(ctx context.Context, opts metav1.ListOptions) (watch.Interface, error)
	convert func(runtime.Object) (string, any, bool)
}

// Collector runs one list/watch loop per kind.
type Collector struct {
	Store   *Store
	Gap     GapFunc
	Backoff time.Duration // delay before relisting after a failure
	specs   []kindSpec

	mu      sync.Mutex
	restart map[string]int
}

// SecretsGVR is the Secret resource read via the metadata-only client.
var SecretsGVR = schema.GroupVersionResource{Version: "v1", Resource: "secrets"}

// New builds a collector. meta may be nil to disable Secret metadata.
func New(cs kubernetes.Interface, md metadata.Interface, store *Store, gap GapFunc) *Collector {
	c := &Collector{Store: store, Gap: gap, Backoff: 2 * time.Second, restart: map[string]int{}}
	c.specs = []kindSpec{
		{KindPod,
			func(ctx context.Context, o metav1.ListOptions) ([]runtime.Object, string, error) {
				l, err := cs.CoreV1().Pods("").List(ctx, o)
				if err != nil {
					return nil, "", err
				}
				return objs(l.Items), l.ResourceVersion, nil
			},
			func(ctx context.Context, o metav1.ListOptions) (watch.Interface, error) {
				return cs.CoreV1().Pods("").Watch(ctx, o)
			},
			convertPod},
		{KindServiceAccount,
			func(ctx context.Context, o metav1.ListOptions) ([]runtime.Object, string, error) {
				l, err := cs.CoreV1().ServiceAccounts("").List(ctx, o)
				if err != nil {
					return nil, "", err
				}
				return objs(l.Items), l.ResourceVersion, nil
			},
			func(ctx context.Context, o metav1.ListOptions) (watch.Interface, error) {
				return cs.CoreV1().ServiceAccounts("").Watch(ctx, o)
			},
			convertNamed},
		{KindRole,
			func(ctx context.Context, o metav1.ListOptions) ([]runtime.Object, string, error) {
				l, err := cs.RbacV1().Roles("").List(ctx, o)
				if err != nil {
					return nil, "", err
				}
				return objs(l.Items), l.ResourceVersion, nil
			},
			func(ctx context.Context, o metav1.ListOptions) (watch.Interface, error) {
				return cs.RbacV1().Roles("").Watch(ctx, o)
			},
			convertRole},
		{KindClusterRole,
			func(ctx context.Context, o metav1.ListOptions) ([]runtime.Object, string, error) {
				l, err := cs.RbacV1().ClusterRoles().List(ctx, o)
				if err != nil {
					return nil, "", err
				}
				return objs(l.Items), l.ResourceVersion, nil
			},
			func(ctx context.Context, o metav1.ListOptions) (watch.Interface, error) {
				return cs.RbacV1().ClusterRoles().Watch(ctx, o)
			},
			convertRole},
		{KindRoleBinding,
			func(ctx context.Context, o metav1.ListOptions) ([]runtime.Object, string, error) {
				l, err := cs.RbacV1().RoleBindings("").List(ctx, o)
				if err != nil {
					return nil, "", err
				}
				return objs(l.Items), l.ResourceVersion, nil
			},
			func(ctx context.Context, o metav1.ListOptions) (watch.Interface, error) {
				return cs.RbacV1().RoleBindings("").Watch(ctx, o)
			},
			convertBinding},
		{KindClusterRoleBinding,
			func(ctx context.Context, o metav1.ListOptions) ([]runtime.Object, string, error) {
				l, err := cs.RbacV1().ClusterRoleBindings().List(ctx, o)
				if err != nil {
					return nil, "", err
				}
				return objs(l.Items), l.ResourceVersion, nil
			},
			func(ctx context.Context, o metav1.ListOptions) (watch.Interface, error) {
				return cs.RbacV1().ClusterRoleBindings().Watch(ctx, o)
			},
			convertBinding},
		{KindAdmissionPolicy,
			func(ctx context.Context, o metav1.ListOptions) ([]runtime.Object, string, error) {
				l, err := cs.AdmissionregistrationV1().ValidatingAdmissionPolicies().List(ctx, o)
				if err != nil {
					return nil, "", err
				}
				return objs(l.Items), l.ResourceVersion, nil
			},
			func(ctx context.Context, o metav1.ListOptions) (watch.Interface, error) {
				return cs.AdmissionregistrationV1().ValidatingAdmissionPolicies().Watch(ctx, o)
			},
			convertNamed},
	}
	if md != nil {
		c.specs = append(c.specs, kindSpec{KindSecret,
			func(ctx context.Context, o metav1.ListOptions) ([]runtime.Object, string, error) {
				l, err := md.Resource(SecretsGVR).Namespace("").List(ctx, o)
				if err != nil {
					return nil, "", err
				}
				return objs(l.Items), l.ResourceVersion, nil
			},
			func(ctx context.Context, o metav1.ListOptions) (watch.Interface, error) {
				return md.Resource(SecretsGVR).Namespace("").Watch(ctx, o)
			},
			convertSecret})
	}
	return c
}

// Kinds lists the kinds this collector watches.
func (c *Collector) Kinds() []string {
	out := make([]string, 0, len(c.specs))
	for _, s := range c.specs {
		out = append(out, s.kind)
	}
	sort.Strings(out)
	return out
}

func objs[T any, PT interface {
	*T
	runtime.Object
}](items []T) []runtime.Object {
	out := make([]runtime.Object, 0, len(items))
	for i := range items {
		out = append(out, PT(&items[i]))
	}
	return out
}

// Run starts every loop and blocks until ctx is done.
func (c *Collector) Run(ctx context.Context) {
	var wg sync.WaitGroup
	for _, s := range c.specs {
		wg.Add(1)
		go func(s kindSpec) {
			defer wg.Done()
			c.loop(ctx, s)
		}(s)
	}
	wg.Wait()
}

func (c *Collector) gap(kind, reason string) {
	if c.Gap != nil {
		c.Gap(kind, redact.String(reason))
	}
}

// loop: list, then watch from the list's resourceVersion. A watch that ends
// is resumed from the last seen resourceVersion (recorded as a gap, because
// delivery across the reconnect is not guaranteed complete); an expired
// resourceVersion (410) forces a relist, recorded as a gap, because
// intermediate states between the old and new snapshots are unobservable.
func (c *Collector) loop(ctx context.Context, s kindSpec) {
	first := true
	for ctx.Err() == nil {
		items, rv, err := s.list(ctx, metav1.ListOptions{})
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			c.gap("list-failed", fmt.Sprintf("list of %s failed (%s); inventory for this kind is incomplete until a list succeeds", s.kind, reasonOf(err)))
			sleep(ctx, c.Backoff)
			continue
		}
		m := map[string]any{}
		for _, o := range items {
			if uid, item, ok := s.convert(o); ok {
				m[uid] = item
			}
		}
		c.Store.Replace(s.kind, m)
		if !first {
			c.gap("relist", fmt.Sprintf("%s was relisted; object states between the previous and the new snapshot were not observed", s.kind))
		}
		first = false
		c.watchUntilExpired(ctx, s, rv)
		if ctx.Err() == nil {
			sleep(ctx, c.Backoff)
		}
	}
}

func (c *Collector) watchUntilExpired(ctx context.Context, s kindSpec, rv string) {
	for ctx.Err() == nil {
		w, err := s.watch(ctx, metav1.ListOptions{ResourceVersion: rv, AllowWatchBookmarks: true})
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if apierrors.IsResourceExpired(err) || apierrors.IsGone(err) {
				c.gap("resource-version-expired", fmt.Sprintf("watch of %s could not resume: resourceVersion expired", s.kind))
			} else {
				c.gap("watch-failed", fmt.Sprintf("watch of %s could not be established (%s)", s.kind, reasonOf(err)))
			}
			return
		}
		expired, next := c.consume(ctx, s, w, rv)
		w.Stop()
		if ctx.Err() != nil {
			return
		}
		if expired {
			return
		}
		rv = next
		c.mu.Lock()
		c.restart[s.kind]++
		c.mu.Unlock()
		c.gap("watch-restarted", fmt.Sprintf("watch of %s ended and was restarted from the last observed resourceVersion; events during the reconnect may be missing", s.kind))
	}
}

// consume processes one watch stream. It returns expired=true if the server
// reported an error that requires a relist.
func (c *Collector) consume(ctx context.Context, s kindSpec, w watch.Interface, rv string) (bool, string) {
	for {
		select {
		case <-ctx.Done():
			return false, rv
		case ev, ok := <-w.ResultChan():
			if !ok {
				return false, rv
			}
			switch ev.Type {
			case watch.Error:
				st := apierrors.FromObject(ev.Object)
				if apierrors.IsResourceExpired(st) || apierrors.IsGone(st) {
					c.gap("resource-version-expired", fmt.Sprintf("watch of %s: resourceVersion expired (410); relisting", s.kind))
				} else {
					c.gap("watch-error", fmt.Sprintf("watch of %s reported an error (%s); relisting", s.kind, reasonOf(st)))
				}
				return true, rv
			case watch.Bookmark:
				if a, err := meta.Accessor(ev.Object); err == nil {
					rv = a.GetResourceVersion()
				}
			case watch.Added, watch.Modified:
				if uid, item, ok := s.convert(ev.Object); ok {
					c.Store.Upsert(s.kind, uid, item)
				}
				rv = rvOf(ev.Object, rv)
			case watch.Deleted:
				if a, err := meta.Accessor(ev.Object); err == nil {
					c.Store.Delete(s.kind, string(a.GetUID()))
				}
				rv = rvOf(ev.Object, rv)
			}
		}
	}
}

// Restarts reports watch restarts per kind (for metrics).
func (c *Collector) Restarts() map[string]int {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := map[string]int{}
	for k, v := range c.restart {
		out[k] = v
	}
	return out
}

func rvOf(o runtime.Object, fallback string) string {
	if a, err := meta.Accessor(o); err == nil && a.GetResourceVersion() != "" {
		return a.GetResourceVersion()
	}
	return fallback
}

func reasonOf(err error) string {
	if st, ok := err.(apierrors.APIStatus); ok {
		return fmt.Sprintf("%s, HTTP %d", st.Status().Reason, st.Status().Code)
	}
	return "transport error"
}

func sleep(ctx context.Context, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

// ---------------------------------------------------------------- converters

func convertPod(o runtime.Object) (string, any, bool) {
	p, ok := o.(*corev1.Pod)
	if !ok || p.UID == "" {
		return "", nil, false
	}
	sa := p.Spec.ServiceAccountName
	if sa == "" {
		sa = "default"
	}
	var auds []string
	seen := map[string]bool{}
	for _, v := range p.Spec.Volumes {
		if v.Projected == nil {
			continue
		}
		for _, src := range v.Projected.Sources {
			if t := src.ServiceAccountToken; t != nil && t.Audience != "" && !seen[t.Audience] {
				seen[t.Audience] = true
				auds = append(auds, redact.String(t.Audience))
			}
		}
	}
	sort.Strings(auds)
	return string(p.UID), Pod{
		Namespace: redact.String(p.Namespace), Name: redact.String(p.Name), UID: redact.String(string(p.UID)),
		ServiceAccount: redact.String(sa), Audiences: auds, Created: p.CreationTimestamp.Time,
	}, true
}

func convertNamed(o runtime.Object) (string, any, bool) {
	a, err := meta.Accessor(o)
	if err != nil || a.GetUID() == "" {
		return "", nil, false
	}
	return string(a.GetUID()), Named{redact.String(a.GetNamespace()), redact.String(a.GetName()), redact.String(string(a.GetUID()))}, true
}

func convertSecret(o runtime.Object) (string, any, bool) {
	// Only *metav1.PartialObjectMetadata is accepted: a full Secret must never
	// be handled here, even by mistake.
	p, ok := o.(*metav1.PartialObjectMetadata)
	if !ok || p.UID == "" {
		return "", nil, false
	}
	return string(p.UID), Secret{Named{redact.String(p.Namespace), redact.String(p.Name), redact.String(string(p.UID))}, p.ResourceVersion}, true
}

func convertRules(in []rbacv1.PolicyRule) ([]Rule, int) {
	var out []Rule
	skipped := 0
	for _, r := range in {
		if len(r.Verbs) == 0 || len(r.Resources) == 0 {
			skipped++
			continue
		}
		rule := Rule{Verbs: clean(r.Verbs), Resources: clean(r.Resources)}
		if len(r.ResourceNames) > 0 {
			rule.ResourceNames = clean(r.ResourceNames)
		}
		out = append(out, rule)
	}
	return out, skipped
}

func clean(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s != "" {
			out = append(out, redact.String(s))
		}
	}
	return out
}

func convertRole(o runtime.Object) (string, any, bool) {
	var n Named
	var rules []rbacv1.PolicyRule
	switch r := o.(type) {
	case *rbacv1.Role:
		n, rules = Named{r.Namespace, r.Name, string(r.UID)}, r.Rules
	case *rbacv1.ClusterRole:
		n, rules = Named{"", r.Name, string(r.UID)}, r.Rules
	default:
		return "", nil, false
	}
	if n.UID == "" {
		return "", nil, false
	}
	conv, skipped := convertRules(rules)
	return n.UID, Role{Named{redact.String(n.Namespace), redact.String(n.Name), n.UID}, conv, skipped}, true
}

func convertBinding(o runtime.Object) (string, any, bool) {
	var n Named
	var ref rbacv1.RoleRef
	var subjects []rbacv1.Subject
	switch b := o.(type) {
	case *rbacv1.RoleBinding:
		n, ref, subjects = Named{b.Namespace, b.Name, string(b.UID)}, b.RoleRef, b.Subjects
	case *rbacv1.ClusterRoleBinding:
		n, ref, subjects = Named{"", b.Name, string(b.UID)}, b.RoleRef, b.Subjects
	default:
		return "", nil, false
	}
	if n.UID == "" || (ref.Kind != "Role" && ref.Kind != "ClusterRole") || (n.Namespace == "" && ref.Kind == "Role") {
		return "", nil, false
	}
	var subs []Subject
	for _, s := range subjects {
		switch s.Kind {
		case "ServiceAccount":
			ns := s.Namespace
			if ns == "" {
				ns = n.Namespace
			}
			if ns == "" {
				continue
			}
			subs = append(subs, Subject{"ServiceAccount", redact.String(s.Name), redact.String(ns)})
		case "User", "Group":
			subs = append(subs, Subject{s.Kind, redact.String(s.Name), ""})
		}
	}
	return n.UID, Binding{Named{redact.String(n.Namespace), redact.String(n.Name), n.UID}, ref.Kind, redact.String(ref.Name), subs}, true
}
