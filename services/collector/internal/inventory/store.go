// Package inventory maintains a metadata-only snapshot of the Kubernetes
// objects AFTERLOCK models, using read-only list/watch.
//
// Converters copy an allowlist of fields out of each API object; nothing else
// (Pod specs, environment variables, annotations, Secret data, managed
// fields) is retained. Secrets are read through the metadata-only API
// (PartialObjectMetadata), so their bodies are never transferred to the
// collector at all.
//
// Kubernetes resourceVersion values are treated as opaque: they are only
// passed back to the API server to resume a watch and compared for equality
// to detect that an object changed. They are never parsed or ordered.
package inventory

import (
	"sort"
	"sync"
	"time"
)

// Pod is the retained metadata of a Pod.
type Pod struct {
	Namespace, Name, UID, ServiceAccount string
	Audiences                            []string
	Created                              time.Time
}

// Named is a namespaced (or cluster-scoped, empty namespace) object.
type Named struct{ Namespace, Name, UID string }

// Rule is a modeled RBAC rule. API groups are intentionally not retained; see
// docs/collector/README.md (this over-approximates permissions).
type Rule struct {
	Verbs, Resources, ResourceNames []string
}

// Role covers Roles (namespaced) and ClusterRoles (empty namespace).
type Role struct {
	Named
	Rules   []Rule
	Skipped int // rules without resources (non-resource URLs) not modeled
}

// Subject of a binding.
type Subject struct{ Kind, Name, Namespace string }

// Binding covers RoleBindings and ClusterRoleBindings (empty namespace).
type Binding struct {
	Named
	RoleKind, RoleName string
	Subjects           []Subject
}

// Secret is Secret metadata. ResourceVersion is opaque.
type Secret struct {
	Named
	ResourceVersion string
}

type secretVersion struct {
	rv      string
	version int
}

// Kinds used as store keys.
const (
	KindPod                = "pods"
	KindServiceAccount     = "serviceaccounts"
	KindRole               = "roles"
	KindClusterRole        = "clusterroles"
	KindRoleBinding        = "rolebindings"
	KindClusterRoleBinding = "clusterrolebindings"
	KindSecret             = "secrets"
	KindAdmissionPolicy    = "validatingadmissionpolicies"
)

// maxPodHistory bounds the deleted-Pod history used for audit correlation.
const maxPodHistory = 100_000

// Store holds the current objects per kind, keyed by UID.
type Store struct {
	mu       sync.Mutex
	objs     map[string]map[string]any
	history  map[string]Pod // every Pod observed during this session, by UID
	versions map[string]secretVersion
	synced   map[string]bool
}

// NewStore returns an empty store.
func NewStore() *Store {
	return &Store{objs: map[string]map[string]any{}, history: map[string]Pod{}, versions: map[string]secretVersion{}, synced: map[string]bool{}}
}

func (s *Store) observeLocked(kind, uid string, item any) {
	switch v := item.(type) {
	case Pod:
		if _, ok := s.history[uid]; ok || len(s.history) < maxPodHistory {
			s.history[uid] = v
		}
	case Secret:
		prev, ok := s.versions[uid]
		switch {
		case !ok:
			s.versions[uid] = secretVersion{v.ResourceVersion, 1}
		case prev.rv != v.ResourceVersion: // opaque equality only
			s.versions[uid] = secretVersion{v.ResourceVersion, prev.version + 1}
		}
	}
}

// Upsert records an Added/Modified object.
func (s *Store) Upsert(kind, uid string, item any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.objs[kind] == nil {
		s.objs[kind] = map[string]any{}
	}
	s.objs[kind][uid] = item
	s.observeLocked(kind, uid, item)
}

// Delete records a Deleted object. Pod history is kept.
func (s *Store) Delete(kind, uid string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.objs[kind], uid)
}

// Replace installs the result of a (re)list.
func (s *Store) Replace(kind string, items map[string]any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.objs[kind] = items
	for uid, item := range items {
		s.observeLocked(kind, uid, item)
	}
	s.synced[kind] = true
}

// Synced reports whether kind completed at least one list.
func (s *Store) Synced(kind string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.synced[kind]
}

// PodsNamed returns every Pod observed this session with namespace/name.
func (s *Store) PodsNamed(namespace, name string) []Pod {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Pod
	for _, p := range s.history {
		if p.Namespace == namespace && p.Name == name {
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UID < out[j].UID })
	return out
}

// Snapshot is the inventory in afterlock.replay/1 inventory.json form, plus
// observations that the analysis model cannot represent.
type Snapshot struct {
	Inventory         map[string]any
	AdmissionPolicies []string // names of observed, unmodeled policies
	SkippedRules      []string // roles with non-resource rules that were not modeled
	Unsynced          []string // kinds that never completed a list
}

func sortedValues[T any](m map[string]any, key func(T) string) []T {
	out := make([]T, 0, len(m))
	for _, v := range m {
		if t, ok := v.(T); ok {
			out = append(out, t)
		}
	}
	sort.Slice(out, func(i, j int) bool { return key(out[i]) < key(out[j]) })
	return out
}

func nsName(n Named) string { return n.Namespace + "\x00" + n.Name + "\x00" + n.UID }

// Snapshot renders the current state deterministically.
func (s *Store) Snapshot(kinds []string) Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	snap := Snapshot{}
	for _, k := range kinds {
		if !s.synced[k] {
			snap.Unsynced = append(snap.Unsynced, k)
		}
	}
	pods := []any{}
	for _, p := range sortedValues(s.objs[KindPod], func(p Pod) string { return p.Namespace + "\x00" + p.Name + "\x00" + p.UID }) {
		m := map[string]any{"namespace": p.Namespace, "name": p.Name, "uid": p.UID, "service_account": p.ServiceAccount}
		if len(p.Audiences) > 0 {
			m["token_audiences"] = p.Audiences
		}
		pods = append(pods, m)
	}
	sas := []any{}
	for _, n := range sortedValues(s.objs[KindServiceAccount], nsName) {
		sas = append(sas, map[string]any{"namespace": n.Namespace, "name": n.Name, "uid": n.UID})
	}
	roles := []any{}
	roleKey := func(r Role) string { return nsName(r.Named) }
	for _, kind := range []string{KindRole, KindClusterRole} {
		for _, r := range sortedValues(s.objs[kind], roleKey) {
			rules := []any{}
			for _, rule := range r.Rules {
				rm := map[string]any{"verbs": rule.Verbs, "resources": rule.Resources}
				if len(rule.ResourceNames) > 0 {
					rm["resource_names"] = rule.ResourceNames
				}
				rules = append(rules, rm)
			}
			m := map[string]any{"name": r.Name, "rules": rules}
			if r.Namespace != "" {
				m["namespace"] = r.Namespace
			}
			roles = append(roles, m)
			if r.Skipped > 0 {
				snap.SkippedRules = append(snap.SkippedRules, kind+"/"+r.Namespace+"/"+r.Name)
			}
		}
	}
	bindings := []any{}
	for _, kind := range []string{KindRoleBinding, KindClusterRoleBinding} {
		for _, b := range sortedValues(s.objs[kind], func(b Binding) string { return nsName(b.Named) }) {
			subs := []any{}
			for _, sub := range b.Subjects {
				sm := map[string]any{"kind": sub.Kind, "name": sub.Name}
				if sub.Namespace != "" {
					sm["namespace"] = sub.Namespace
				}
				subs = append(subs, sm)
			}
			m := map[string]any{"name": b.Name, "role_kind": b.RoleKind, "role_name": b.RoleName, "subjects": subs}
			if b.Namespace != "" {
				m["namespace"] = b.Namespace
			}
			bindings = append(bindings, m)
		}
	}
	secrets := []any{}
	for _, sec := range sortedValues(s.objs[KindSecret], func(x Secret) string { return nsName(x.Named) }) {
		secrets = append(secrets, map[string]any{"namespace": sec.Namespace, "name": sec.Name, "uid": sec.UID, "version": s.versions[sec.UID].version})
	}
	for _, p := range sortedValues(s.objs[KindAdmissionPolicy], nsName) {
		snap.AdmissionPolicies = append(snap.AdmissionPolicies, p.Name)
	}
	snap.Inventory = map[string]any{
		"service_accounts":   sas,
		"pods":               pods,
		"controllers":        []any{},
		"roles":              roles,
		"bindings":           bindings,
		"secrets":            secrets,
		"services":           []any{},
		"admission_policies": []any{},
	}
	return snap
}
