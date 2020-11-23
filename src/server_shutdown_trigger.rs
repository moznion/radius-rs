use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

#[derive(Copy, Clone)]
pub struct ServerShutdownTrigger {
    should_shutdown: bool
}

impl ServerShutdownTrigger {
    pub(crate) fn new() -> Self {
        ServerShutdownTrigger {
            should_shutdown: false,
        }
    }

    pub(crate) fn trigger_shutdown(&mut self) {
        self.should_shutdown = true;
    }
}

impl Future for ServerShutdownTrigger {
    type Output = Option<()>;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.should_shutdown {
            true => Poll::from(Some(())),
            false => Poll::from(None),
        }
    }
}
