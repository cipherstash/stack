package guest

// The testing seam: a way to refuse the guest's growth without a lock
// limit, so the bookkeeping of a refused growth — the allocator's and a
// client's — can be exercised on every host. Exported because the tests
// that need it live in the public packages, which cannot reach an
// allocator's backing; internal visibility keeps it out of any API.

// Refusing stands in front of an allocator's backing and refuses, as
// Strict does, any commit past a size: nil buffer, the reason as the lock
// error, nothing admitted. Allowed, it delegates again.
type Refusing struct {
	backend
	past    uint64
	reason  error
	refuse  bool
	refused int
}

func (b *Refusing) commit(size uint64) ([]byte, error) {
	if b.refuse && size > b.past {
		b.refused++
		return nil, b.reason
	}
	return b.backend.commit(size)
}

// Allow lifts the refusal: later growths go through to the real backing.
func (b *Refusing) Allow() { b.refuse = false }

// Refused is how many growths were refused.
func (b *Refusing) Refused() int { return b.refused }

// Reason is the error every refused growth reported.
func (b *Refusing) Reason() error { return b.reason }

// RefuseGrowth puts a Refusing in front of alloc's backing, set to refuse
// any growth past what is committed now, with reason as the refusal. Call
// it on the guest's goroutine, between calls, as the backing is used.
func RefuseGrowth(alloc *Allocator, reason error) *Refusing {
	refusing := &Refusing{backend: alloc.backing, past: alloc.backing.(sized).size(), reason: reason, refuse: true}
	alloc.backing = refusing
	return refusing
}

// sized is what the seam needs of a backing to know where it stands.
type sized interface{ size() uint64 }

func (m *mappedMemory) size() uint64 { return m.committed }
func (m *heapMemory) size() uint64   { return uint64(len(m.buf)) }
