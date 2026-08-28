//! The cipher-session table behind the ABI's handle scheme, generic over the
//! cipher it stores so the handle-allocation invariants can be unit-tested
//! natively (the wasm32 ABI instantiates it with
//! `StackCipher<StackKms<HostTokenStrategy, WasiHostConnection>>`).
//!
//! Mirrors the vitaminc guest's session table (`vcencrypt/guest/src/
//! sessions.rs`); extracting the shared implementation into a common
//! vitaminc crate is a planned follow-up in that repository — see the plan's
//! Phase 3 notes.

use std::collections::hash_map::Entry;
use std::collections::HashMap;

use crate::status::STATUS_INTERNAL;

pub(crate) struct Sessions<C> {
    next: u32,
    ciphers: HashMap<u32, C>,
}

impl<C> Sessions<C> {
    pub(crate) fn new() -> Self {
        // Handle ids start at 1 so a zero high-field can never be a valid
        // handle (see the abi result encoding).
        Sessions {
            next: 1,
            ciphers: HashMap::new(),
        }
    }

    /// Insert a cipher under a fresh handle id.
    ///
    /// Refuses at id exhaustion rather than wrapping or saturating: a reused
    /// id would alias a live handle and silently displace its session —
    /// sealing new data under the wrong keyset and orphaning everything the
    /// displaced cipher had sealed. `next` only advances on success, and the
    /// occupancy check makes the no-aliasing invariant explicit rather than
    /// assumed. (The final id, `u32::MAX`, is sacrificed to keep the
    /// arithmetic simple; ~4.3e9 handles precede it.)
    pub(crate) fn insert(&mut self, cipher: C) -> Result<u32, u32> {
        let handle = self.next;
        let bumped = handle.checked_add(1).ok_or(STATUS_INTERNAL)?;
        match self.ciphers.entry(handle) {
            Entry::Occupied(_) => Err(STATUS_INTERNAL),
            Entry::Vacant(slot) => {
                slot.insert(cipher);
                self.next = bumped;
                Ok(handle)
            }
        }
    }

    pub(crate) fn get(&self, handle: u32) -> Option<&C> {
        self.ciphers.get(&handle)
    }

    pub(crate) fn remove(&mut self, handle: u32) {
        self.ciphers.remove(&handle);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handles_start_at_one_and_increment() {
        let mut s = Sessions::new();
        assert_eq!(s.insert("a"), Ok(1));
        assert_eq!(s.insert("b"), Ok(2));
        assert!(s.get(1).is_some());
        s.remove(1);
        assert!(s.get(1).is_none());
        assert!(s.get(2).is_some());
    }

    #[test]
    fn handle_ids_are_never_reused_at_exhaustion() {
        let mut s = Sessions::new();
        s.next = u32::MAX - 1;
        let last = s.insert("last").expect("last issuable id");
        assert_eq!(last, u32::MAX - 1);
        // At exhaustion the table must refuse rather than alias a live
        // handle (a saturating or wrapping counter would silently displace
        // the session and seal under the wrong keyset).
        assert_eq!(s.insert("next"), Err(STATUS_INTERNAL));
        assert!(s.get(last).is_some(), "live session must not be displaced");
    }
}
