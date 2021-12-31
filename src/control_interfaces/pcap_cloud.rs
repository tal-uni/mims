use super::pcap;

use tokio_stream::{Stream, StreamExt};

/// Represents an action that a cloud can perform on a handle.
enum CloudAction {
    /// Indicates that new data has been recieved.
    Forward(Result<(std::time::SystemTime, pcap::Data), pcap::CaptureError>),
    /// Indicates that the cloud recieved data to inject.
    Inject(pcap::Data),
}

pub struct Cloud<S: Stream<Item = pcap::Data>> {
    wrapped_handle: pcap::CaptureHandle,
    injection_receiver: S,
    packet_output:
        tokio::sync::mpsc::Sender<Result<(std::time::SystemTime, pcap::Data), pcap::CaptureError>>,
}

impl<S: Stream<Item = pcap::Data> + Unpin> Cloud<S> {
    pub fn new(
        handle: pcap::CaptureHandle,
        injections: S,
    ) -> (
        Cloud<S>,
        super::mpsc::Receiver<Result<(std::time::SystemTime, pcap::Data), pcap::CaptureError>>,
    ) {
        let (incoming_snd, incoming_rcv) = super::mpsc::Receiver::<
            Result<(std::time::SystemTime, pcap::Data), pcap::CaptureError>,
        >::new_bounded(1000);
        (
            Cloud {
                wrapped_handle: handle,
                injection_receiver: injections,
                packet_output: incoming_snd,
            },
            incoming_rcv,
        )
    }

    async fn get_next(&mut self) -> Option<CloudAction> {
        tokio::select! {
            biased;
            p = self.wrapped_handle.next() => Some(CloudAction::Forward(p)),
            Some(i) = self.injection_receiver.next() => Some(CloudAction::Inject(i)),
            else => None
        }
    }

    /// The method runs the cloud. This means that it waits for data from both pcap and the injection stream and applies the appropriate action on the handle.
    pub async fn run(mut self) {
        while let Some(a) = self.get_next().await {
            match a {
                CloudAction::Forward(p) => {
                    match self.packet_output.send(p).await {
                        _ => {}
                    };
                }
                CloudAction::Inject(i) => match self.wrapped_handle.inject(i) {
                    _ => {}
                },
            }
        }
    }
}
