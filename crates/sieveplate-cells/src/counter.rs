//! CounterCell — the canonical transactional cell.
//!
//! Verbs (bincode payload):
//! - `add`   : payload = u64 LE delta → count += delta
//! - `get`   : empty payload → reply with count (u64 LE)
//! - `reset` : empty payload → count = 0
//! - `poison`: returns Err → turn rolls back (count unchanged)
//! - `panic` : panics → turn rolls back (count unchanged)

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use sieveplate_core::{Cell, CellError, CellFactory, Envelope, TurnCtx};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CounterState {
    pub count: u64,
    pub turns: u64,
}

pub struct CounterCell {
    pub state: CounterState,
}

#[async_trait]
impl Cell for CounterCell {
    async fn handle(&mut self, env: &Envelope, ctx: &mut TurnCtx<'_>) -> Result<(), CellError> {
        self.state.turns += 1;
        match env.kind.as_str() {
            "add" => {
                let delta = if env.payload.len() >= 8 {
                    u64::from_le_bytes(env.payload[..8].try_into().unwrap())
                } else {
                    1
                };
                self.state.count += delta;
            }
            "get" => ctx.set_reply(self.state.count.to_le_bytes().to_vec()),
            "reset" => self.state.count = 0,
            "poison" => return Err(CellError::Poison),
            "panic" => panic!("deliberate panic for rollback test"),
            other => return Err(CellError::Other(format!("counter: unknown verb '{other}'"))),
        }
        Ok(())
    }

    fn snapshot(&self) -> Result<Vec<u8>, CellError> {
        bincode::serialize(&self.state).map_err(|e| CellError::Other(e.to_string()))
    }

    fn restore(&mut self, data: &[u8]) -> Result<(), CellError> {
        self.state = bincode::deserialize(data).map_err(|e| CellError::Other(e.to_string()))?;
        Ok(())
    }
}

pub struct CounterFactory;

impl CellFactory for CounterFactory {
    fn build(&self) -> Result<sieveplate_core::BoxedCell, CellError> {
        Ok(Box::new(CounterCell {
            state: CounterState::default(),
        }))
    }

    /// Descriptor contributes to the L7 closure hash: changing this cell's
    /// semantics changes the system closure.
    fn descriptor(&self) -> String {
        "counter/v1/{state:{count:u64,turns:u64},verbs:[add,get,reset,poison,panic]}".into()
    }
}
