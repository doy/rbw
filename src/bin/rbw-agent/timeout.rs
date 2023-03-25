use futures_util::StreamExt as _;

#[derive(Debug, Hash, Eq, PartialEq, Copy, Clone)]
enum Streams {
    Requests,
    Timer,
}

#[derive(Debug)]
enum Action {
    Set(std::time::Duration),
    Clear,
}

pub struct Timeout {
    req_w: tokio::sync::mpsc::UnboundedSender<Action>,
}

impl Timeout {
    pub fn new() -> (Self, tokio::sync::mpsc::UnboundedReceiver<()>) {
        let (req_w, req_r) = tokio::sync::mpsc::unbounded_channel();
        let (timer_w, timer_r) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            enum Event {
                Request(Action),
                Timer,
            }
            let mut stream = tokio_stream::StreamMap::new();
            stream.insert(
                Streams::Requests,
                tokio_stream::wrappers::UnboundedReceiverStream::new(req_r)
                    .map(Event::Request)
                    .boxed(),
            );
            while let Some(event) = stream.next().await {
                match event {
                    (_, Event::Request(Action::Set(dur))) => {
                        stream.insert(
                            Streams::Timer,
                            futures_util::stream::once(tokio::time::sleep(
                                dur,
                            ))
                            .map(|_| Event::Timer)
                            .boxed(),
                        );
                    }
                    (_, Event::Request(Action::Clear)) => {
                        stream.remove(&Streams::Timer);
                    }
                    (_, Event::Timer) => {
                        timer_w.send(()).unwrap();
                    }
                }
            }
        });
        (Self { req_w }, timer_r)
    }

    pub fn set(&self, dur: std::time::Duration) {
        self.req_w.send(Action::Set(dur)).unwrap();
    }

    pub fn clear(&self) {
        self.req_w.send(Action::Clear).unwrap();
    }
}
