use futures_util::StreamExt as _;

// How often a running timer compares its deadline with the wall clock.
// Requests check the deadline themselves before touching the keys, so this
// only bounds how long the keys stay in memory after a wake from sleep.
const WALL_CLOCK_CHECK_INTERVAL: std::time::Duration =
    std::time::Duration::from_secs(10);

#[derive(Debug, Hash, Eq, PartialEq, Copy, Clone)]
enum Streams {
    Requests,
    Timer,
}

#[derive(Debug)]
enum Action {
    Set(std::time::Duration, Option<std::time::SystemTime>),
    Clear,
}

// Tokio's timers run on a monotonic clock that stops while the computer
// sleeps, so a timer started before a night of sleep would still have most
// of its time left in the morning. A timer here expires at whichever comes
// first: its duration on the monotonic clock, which a clock change cannot
// extend, or its deadline on the wall clock, which counts sleep.
pub struct Timeout {
    req_w: tokio::sync::mpsc::UnboundedSender<Action>,
    deadline: std::sync::Mutex<Option<std::time::SystemTime>>,
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
                    (_, Event::Request(Action::Set(dur, deadline))) => {
                        stream.insert(
                            Streams::Timer,
                            futures_util::stream::once(expiry(dur, deadline))
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
        (
            Self {
                req_w,
                deadline: std::sync::Mutex::new(None),
            },
            timer_r,
        )
    }

    pub fn set(&self, dur: std::time::Duration) {
        let deadline = std::time::SystemTime::now().checked_add(dur);
        *self.deadline.lock().unwrap() = deadline;
        self.req_w.send(Action::Set(dur, deadline)).unwrap();
    }

    pub fn clear(&self) {
        *self.deadline.lock().unwrap() = None;
        self.req_w.send(Action::Clear).unwrap();
    }

    // Whether the wall-clock deadline has passed, even if the timer has not
    // noticed yet because the computer just woke up.
    pub fn expired(&self) -> bool {
        self.deadline
            .lock()
            .unwrap()
            .is_some_and(|deadline| std::time::SystemTime::now() >= deadline)
    }
}

async fn expiry(
    dur: std::time::Duration,
    deadline: Option<std::time::SystemTime>,
) {
    let wall_clock = async {
        let Some(deadline) = deadline else {
            return std::future::pending().await;
        };
        while let Ok(remaining) =
            deadline.duration_since(std::time::SystemTime::now())
        {
            if remaining.is_zero() {
                break;
            }
            tokio::time::sleep(remaining.min(WALL_CLOCK_CHECK_INTERVAL))
                .await;
        }
    };
    tokio::select! {
        () = tokio::time::sleep(dur) => {}
        () = wall_clock => {}
    }
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn expires_after_its_duration() {
        let (timeout, mut timer_r) = super::Timeout::new();
        timeout.set(std::time::Duration::from_millis(10));
        assert!(!timeout.expired());
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            timer_r.recv(),
        )
        .await
        .unwrap()
        .unwrap();
        timeout.clear();
        assert!(!timeout.expired());
    }

    #[tokio::test]
    async fn wall_clock_deadline_in_the_past_expires_at_once() {
        // what a timer sees after the computer slept through its deadline
        let past = std::time::SystemTime::now()
            .checked_sub(std::time::Duration::from_secs(60));
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            super::expiry(std::time::Duration::from_secs(3600), past),
        )
        .await
        .unwrap();
    }
}
