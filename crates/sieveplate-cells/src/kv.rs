//! KvCell — a small key/value store; bigger state for snapshot benchmarks.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use sieveplate_core::{Cell, CellError, CellFactory, Envelope, TurnCtx};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KvState {
    pub map: BTreeMap<String, String>,
}

pub struct KvCell {
    pub state: KvState,
}

#[async_trait]
impl Cell for KvCell {
    async fn handle(&mut self, env: &Envelope, ctx: &mut TurnCtx<'_>) -> Result<(), CellError> {
        match env.kind.as_str() {
            "put" => {
                // payload: json {"k": "...", "v": "..."}
                let v: serde_json::Value = serde_json::from_slice(&env.payload)
                    .map_err(|e| CellError::Other(format!("put payload: {e}")))?;
                let k = v
                    .get("k")
                    .and_then(|x| x.as_str())
                    .ok_or_else(|| CellError::Other("put missing 'k'".into()))?
                    .to_string();
                let val = v
                    .get("v")
                    .and_then(|x| x.as_str())
                    .unwrap_or_default()
                    .to_string();
                self.state.map.insert(k, val);
            }
            "get" => {
                let k = String::from_utf8(env.payload.clone())
                    .map_err(|_| CellError::Other("get payload must be utf-8 key".into()))?;
                let v = self.state.map.get(&k).cloned().unwrap_or_default();
                ctx.set_reply(v.into_bytes());
            }
            "del" => {
                let k = String::from_utf8(env.payload.clone()).unwrap_or_default();
                self.state.map.remove(&k);
            }
            "len" => {
                ctx.set_reply((self.state.map.len() as u64).to_le_bytes().to_vec());
            }
            other => return Err(CellError::Other(format!("kv: unknown verb '{other}'"))),
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

pub struct KvFactory;

impl CellFactory for KvFactory {
    fn build(&self) -> Result<sieveplate_core::BoxedCell, CellError> {
        Ok(Box::new(KvCell {
            state: KvState::default(),
        }))
    }

    fn descriptor(&self) -> String {
        "kv/v1/{state:{map:{string:string}},verbs:[put,get,del,len]}".into()
    }
}
