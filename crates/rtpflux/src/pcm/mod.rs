//! PCM streams: a media endpoint's audio to an external service (speech
//! recognition, a voice bot) and the service's audio back, over a Unix
//! socket, with the signal processing and the socket I/O on a few shared
//! shard threads (see [`stream`] and [`shard`]) and the frames of
//! [`frame`].

pub mod frame;
pub mod inband;
pub mod mixer;
pub mod receive;
pub mod shard;
pub mod stream;
