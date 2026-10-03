//! The SensePump: maps signals to envelopes via declarative routes and
//! delivers them through the fabric. This is the bridge between the outer
//! world (L1) and the cell grid (L5/L6).

use std::sync::Arc;

use tokio::sync::mpsc;

use sieveplate_core::{Envelope, Port, Route};
use sieveplate_store::EventLog;

use crate::sources::Signal;

/// One declarative route: signals from `sense_name` are delivered to
/// `target` as `msg_kind` (default: the signal's own name).
#[derive(Debug, Clone)]
pub struct SignalRoute {
    pub sense_name: String,
    pub target: Port,
    pub msg_kind: Option<String>,
}

/// Pump signals → envelopes → fabric. Run inside a tokio task.
pub struct SensePump {
    rx: mpsc::Receiver<Signal>,
    fabric: Arc<dyn Route>,
    routes: Vec<SignalRoute>,
    log: Option<Arc<EventLog>>,
}

impl SensePump {
    pub fn new(
        rx: mpsc::Receiver<Signal>,
        fabric: Arc<dyn Route>,
        routes: Vec<SignalRoute>,
        log: Option<Arc<EventLog>>,
    ) -> Self {
        SensePump {
            rx,
            fabric,
            routes,
            log,
        }
    }

    /// Run until the signal channel closes (all sources shut down).
    pub async fn run(mut self) {
        while let Some(sig) = self.rx.recv().await {
            let matching: Vec<&SignalRoute> = self
                .routes
                .iter()
                .filter(|r| r.sense_name == sig.source)
                .collect();
            let routes: Vec<SignalRoute> = if matching.is_empty() {
                // Unrouted signals go nowhere; log for observability.
                tracing::debug!(sense = %sig.source, "signal has no route");
                continue;
            } else {
                matching.into_iter().cloned().collect()
            };
            for r in routes {
                let kind = r.msg_kind.clone().unwrap_or_else(|| sig.name.clone());
                let env = Envelope::new(r.target.clone(), kind, sig.payload.clone());
                if let Err(e) = self.fabric.deliver(env).await {
                    tracing::warn!(error = %e, "signal delivery failed");
                } else {
                    if let Some(log) = &self.log {
                        let _ = log.append(
                            "sense.fire",
                            vec![
                                ("source".into(), sig.source.clone()),
                                ("name".into(), sig.name.clone()),
                            ],
                        );
                    }
                }
            }
        }
        tracing::debug!("sense pump exiting");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// A route that records deliveries (test double).
    struct RecordingRoute {
        seen: Mutex<Vec<String>>,
    }

    #[async_trait::async_trait]
    impl Route for RecordingRoute {
        async fn deliver(&self, env: Envelope) -> Result<(), sieveplate_core::CellError> {
            self.seen
                .lock()
                .unwrap()
                .push(format!("{}:{}", env.to.cell, env.kind));
            Ok(())
        }
        fn pipe_continuation(
            &self,
            _pid: sieveplate_core::PromiseId,
            _cont: sieveplate_core::Continuation,
        ) -> Result<(), sieveplate_core::CellError> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn routes_signals_to_targets() {
        let (tx, rx) = mpsc::channel(16);
        let route = Arc::new(RecordingRoute {
            seen: Mutex::new(Vec::new()),
        });
        let routes = vec![SignalRoute {
            sense_name: "tick".into(),
            target: Port::new("h1", "core", "counter"),
            msg_kind: Some("add".into()),
        }];
        let pump = SensePump::new(rx, route.clone(), routes, None);
        let handle = tokio::spawn(pump.run());

        tx.send(Signal {
            source: "tick".into(),
            name: "tick".into(),
            payload: vec![],
        })
        .await
        .unwrap();
        drop(tx); // closes channel → pump exits
        handle.await.unwrap();
        let seen = route.seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0], "counter:add");
    }
}
