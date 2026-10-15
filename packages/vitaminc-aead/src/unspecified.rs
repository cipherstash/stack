/// The opaque error of a cipher: it reveals nothing about what failed.
///
/// It is crucial when returning an error from a cipher operation that it
/// does not reveal any details about the failure, as those can lead to side
/// channel attacks: a wrong key, a wrong AAD and a tampered leaf are
/// indistinguishable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unspecified;

impl std::fmt::Display for Unspecified {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Unspecified error")
    }
}

impl std::error::Error for Unspecified {}
