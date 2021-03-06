use tokio_stream::{Stream, StreamExt};

pub struct Agent<S>
where
    S: Stream,
{
    input: S,
}

impl<S: Stream> Agent<S> {
    pub fn new(input: S) -> Agent<S> {
        Agent { input }
    }
}

impl<S: Stream + Unpin> Agent<S>
where
    S::Item: std::fmt::Display,
{
    pub async fn run(mut self) -> () {
        while let Some(thing) = self.input.next().await {
            println!("{}", thing)
        }
    }
}
