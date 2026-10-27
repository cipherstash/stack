package control

import "sync"

// Copies of a creation result share a single extraction right. Both typed
// handoff and byte export consume it, including under concurrent callers.
type creationSecret struct {
	mu    sync.Mutex
	bytes []byte
}

func (s *creationSecret) take() ([]byte, error) {
	if s == nil {
		return nil, ErrSecretConsumed
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.bytes) == 0 {
		return nil, ErrSecretConsumed
	}

	bytes := s.bytes
	s.bytes = nil

	return bytes, nil
}

func (s *creationSecret) wipe() {
	if s == nil {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	clear(s.bytes)
	s.bytes = nil
}
