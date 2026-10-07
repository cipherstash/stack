package gensupport

import "io"

// SetNotices redirects the notices for a test and returns the previous writer.
func SetNotices(w io.Writer) io.Writer {
	noticesMu.Lock()
	defer noticesMu.Unlock()
	prev := notices
	notices = w
	return prev
}

// ResetNoticed forgets which notices were printed.
func ResetNoticed() {
	noticed.Range(func(k, _ any) bool {
		noticed.Delete(k)
		return true
	})
}
