package policy

import "sync/atomic"

// Holder holds the active policy and lets it be replaced while requests are
// in flight. A swap is atomic: every check sees either the old or the new
// policy in full, never a mix of the two.
type Holder struct {
	p atomic.Pointer[Policy]
}

// NewHolder returns a Holder with p active.
func NewHolder(p *Policy) *Holder {
	h := &Holder{}
	h.p.Store(p)
	return h
}

// Load returns the active policy.
func (h *Holder) Load() *Policy { return h.p.Load() }

// Swap makes p active. Rate-limit state carries over, so a reload cannot be
// used to reset a caller's budget.
func (h *Holder) Swap(p *Policy) {
	if old := h.p.Load(); old != nil && old.limiter != nil {
		p.limiter = old.limiter
	}
	h.p.Store(p)
}
