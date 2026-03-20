use crate::cluster::protocol::*;

pub struct WorkerClient {
    client: reqwest::Client,
    base_url: String,
    pub worker_id: String,
}

impl WorkerClient {
    pub fn new(coordinator_url: &str) -> Self {
        WorkerClient {
            client: reqwest::Client::new(),
            base_url: coordinator_url.trim_end_matches('/').to_string(),
            worker_id: format!("worker-{}", rand_id()),
        }
    }

    pub async fn get_work(&self) -> Result<Option<WorkAssignment>, reqwest::Error> {
        let resp = self.client
            .get(format!("{}/work", self.base_url))
            .send()
            .await?
            .json::<Option<WorkAssignment>>()
            .await?;
        Ok(resp)
    }

    pub async fn post_result(&self, result: WorkResult) -> Result<bool, reqwest::Error> {
        let done = self.client
            .post(format!("{}/result", self.base_url))
            .json(&result)
            .send()
            .await?
            .json::<bool>()
            .await?;
        Ok(done)
    }
}

fn rand_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let t = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    format!("{:x}", t.as_nanos() & 0xFFFFFFFF)
}
