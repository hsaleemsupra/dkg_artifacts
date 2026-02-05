use async_trait::async_trait;

#[async_trait]
pub trait Task {
    async fn run(mut self);
}

pub trait TaskSpawner: Send + Sync + 'static {
    fn spawn<T: Task + 'static>(&self, task: T);
}

#[derive(Default)]
pub struct TokioTaskSpawner;

impl TaskSpawner for TokioTaskSpawner {
    fn spawn<T: Task + 'static>(&self, task: T) {
        tokio::spawn(T::run(task));
    }
}
