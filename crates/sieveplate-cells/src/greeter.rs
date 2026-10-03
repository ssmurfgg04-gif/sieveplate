//! GreeterCell — the Phase-1 vertical-slice actor: sleeps, wakes on
//! message, greets transactionally.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use sieveplate_core::{Cell, CellError, CellFactory, Envelope, TurnCtx};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GreeterState {
    pub greeted: Vec<String>,
}

pub struct GreeterCell {
    pub state: GreeterState,
}

#[async_trait]
impl Cell for GreeterCell {
    async fn handle(&mut self, env: &Envelope, ctx: &mut TurnCtx<'_>) -> Result<(), CellError> {
        match env.kind.as_str() {
            // Payload is a UTF-8 name; reply is a greeting.
            "greet" => {
                let name = String::from_utf8(env.payload.clone())
                    .map_err(|_| CellError::Other("greet payload must be utf-8 name".into()))?;
                self.state.greeted.push(name.clone());
                ctx.set_reply(format!("hello, {name}").into_bytes());
            }
            // Tick from a sense source: no reply, just record.
            "tick" => {
                self.state.greeted.push("<tick>".into());
            }
            "count" => {
                ctx.set_reply((self.state.greeted.len() as u64).to_le_bytes().to_vec());
            }
            other => return Err(CellError::Other(format!("greeter: unknown verb '{other}'"))),
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

pub struct GreeterFactory;

impl CellFactory for GreeterFactory {
    fn build(&self) -> Result<sieveplate_core::BoxedCell, CellError> {
        Ok(Box::new(GreeterCell {
            state: GreeterState::default(),
        }))
    }

    fn descriptor(&self) -> String {
        "greeter/v1/{state:{greeted:[string]},verbs:[greet,tick,count]}".into()
    }
}
