//! EchoCell — reflects any payload back; the relay in pipelining demos.

use async_trait::async_trait;

use sieveplate_core::{Cell, CellError, CellFactory, Envelope, TurnCtx};

#[derive(Debug, Default)]
pub struct EchoCell {
    pub echoed: u64,
}

#[async_trait]
impl Cell for EchoCell {
    async fn handle(&mut self, env: &Envelope, ctx: &mut TurnCtx<'_>) -> Result<(), CellError> {
        self.echoed += 1;
        // `sleep` verb: first 8 bytes = milliseconds (u64 LE). Lets tests
        // hold a call in flight deterministically, then kill the peer.
        if env.kind == "sleep" && env.payload.len() >= 8 {
            let ms = u64::from_le_bytes(env.payload[..8].try_into().unwrap());
            tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
        }
        ctx.set_reply(env.payload.clone());
        Ok(())
    }

    fn snapshot(&self) -> Result<Vec<u8>, CellError> {
        Ok(self.echoed.to_le_bytes().to_vec())
    }

    fn restore(&mut self, data: &[u8]) -> Result<(), CellError> {
        if data.len() >= 8 {
            self.echoed = u64::from_le_bytes(data[..8].try_into().unwrap());
        }
        Ok(())
    }
}

pub struct EchoFactory;

impl CellFactory for EchoFactory {
    fn build(&self) -> Result<sieveplate_core::BoxedCell, CellError> {
        Ok(Box::new(EchoCell::default()))
    }

    fn descriptor(&self) -> String {
        "echo/v1/{state:{echoed:u64},verbs:[*]}".into()
    }
}
