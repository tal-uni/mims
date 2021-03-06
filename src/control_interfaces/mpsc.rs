use std::pin::Pin;
use std::task::Poll;
use tokio_stream::Stream;

pub struct Receiver<T> {
    rcv: tokio::sync::mpsc::Receiver<T>,
}

impl<T> Stream for Receiver<T> {
    type Item = T;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        self.rcv.poll_recv(cx)
    }
}

impl<T> Receiver<T> {
    pub fn new_bounded(cap: usize) -> (tokio::sync::mpsc::Sender<T>, Receiver<T>) {
        let (raw_snd, raw_rcv) = tokio::sync::mpsc::channel(cap);
        (raw_snd, Receiver { rcv: raw_rcv })
    }
   #[allow(dead_code)]
    pub fn consume(self) -> tokio::sync::mpsc::Receiver<T> {
        self.rcv
    }
}
