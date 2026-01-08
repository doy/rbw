use std::time::SystemTime;
use futures_util::StreamExt as _;
use tokio::time;

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
                            futures_util::stream::once(async move {
                                // Need to poll the system time here as otherwise,
                                // e.g. long-sleep with tokio::time::sleep(dur) or polling Instant::elapsed(),
                                // the timer will not continue to run down while the system is in sleep or hibernate
                                let start = SystemTime::now();
                                loop {
                                    match start.elapsed() {
                                        Ok(elapsed) => {
                                            if elapsed >= dur {
                                                break;
                                            }

                                            tokio::time::sleep(time::Duration::from_secs(1)).await;
                                        }
                                        // Clock went backwards, expire timer immediately just to be cautious
                                        Err(e) => {
                                            eprintln!("Backwards time jump by {:.2}s detected, immediately expire timer.", e.duration().as_secs_f32());
                                            break
                                        }
                                    }
                                }
                            })
                            .map(|()| Event::Timer)
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
