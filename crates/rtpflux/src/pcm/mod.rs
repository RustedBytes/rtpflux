//! PCM streams: a media endpoint's audio to an external service (speech
//! recognition, a voice bot) and the service's audio back, over a Unix
//! socket, with the signal processing on the stream's own threads (see
//! [`stream`]) and the frames of [`frame`].

pub mod frame;
pub mod inband;
pub mod mixer;
pub mod receive;
pub mod stream;
