use std::time::SystemTime;

use crate::Digest;
use serde::Serialize;
use serde_with::serde_as;

/// A representation of a generation within the tree
pub type CommitId = Digest;

/// Identifies a cryptographically secured set of transactions on the tree.
#[serde_as]
#[derive(Serialize, Deserialize, Debug)]
pub struct Commit<CustomData>
where
    CustomData: Serialize,
{
    pub(super) id: CommitId,
    pub(super) metadata: CommitMetadata<CustomData>,
}

/// All the protected parts of a [`Commit`]
#[serde_as]
#[derive(Serialize, Deserialize, Debug)]
pub struct CommitMetadata<CustomData>
where
    CustomData: Serialize,
{
    pub(crate) previous: Option<CommitId>,
    pub(crate) message: Option<String>,
    #[serde_as(as = "serde_with::TimestampSecondsWithFrac<f64>")]
    pub(crate) time: SystemTime,

    pub(crate) custom_data: CustomData,
}

impl<CustomData: Serialize + Default> Default for CommitMetadata<CustomData> {
    fn default() -> Self {
        Self {
            time: SystemTime::now(),
            previous: None,
            message: None,
            custom_data: CustomData::default(),
        }
    }
}

/// Enum to navigate the versions that are available in an Infinitree
#[allow(unused)]
pub enum CommitFilter {
    /// On querying, all versions will be crawled. This is the
    /// default.
    All,
    /// Only a single generation will be looked at during querying.
    Single(CommitId),
    /// All generations up to and including the given one will be queried.
    UpTo(CommitId),
    /// Only use generations between the two given versions.
    /// The first parameter **must** be earlier generation than the
    /// second.
    Range(CommitId, CommitId),
}

impl Default for CommitFilter {
    fn default() -> Self {
        Self::All
    }
}

/// A commit message. Mostly equivalent to Option<String>.
///
/// The main reason for a separate wrapper type is being able to use
/// versatile `From<T>` implementations that in return make the
/// `Infinitree` API nicer to use.
pub enum Message {
    /// No commit message.
    Empty,
    /// Use the `String` parameter as commit message
    Some(String),
}

impl From<&str> for Message {
    fn from(from: &str) -> Self {
        Self::Some(from.to_string())
    }
}

impl From<Option<String>> for Message {
    fn from(from: Option<String>) -> Self {
        match from {
            Some(s) => Self::Some(s),
            None => Self::Empty,
        }
    }
}

impl From<String> for Message {
    fn from(from: String) -> Self {
        Self::Some(from)
    }
}

impl From<Message> for Option<String> {
    fn from(from: Message) -> Option<String> {
        match from {
            Message::Empty => None,
            Message::Some(s) => Some(s),
        }
    }
}
