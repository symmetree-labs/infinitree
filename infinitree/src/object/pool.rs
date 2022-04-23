use super::{ObjectError, Result};
use flume as mpsc;
use std::{
    ops::{Deref, DerefMut},
    sync::Arc,
};

pub(crate) mod buffer;
pub(crate) mod reader;
pub(crate) mod writer;

pub struct Pool<O> {
    enqueue: mpsc::Sender<O>,
    dequeue: mpsc::Receiver<O>,
    items: usize,
    constructor: Option<Arc<dyn Fn() -> O + Send + Sync>>,
}

impl<O> Clone for Pool<O> {
    fn clone(&self) -> Self {
        Self {
            enqueue: self.enqueue.clone(),
            dequeue: self.dequeue.clone(),
            items: self.items,
            constructor: self.constructor.clone(),
        }
    }
}

impl<O: 'static + Clone> Pool<O> {
    pub fn new(items: usize, instance: O) -> Result<Self> {
        let (enqueue, dequeue) = mpsc::bounded(items);

        for _ in 0..(items - 1) {
            enqueue
                .send(instance.clone())
                .map_err(|_| ObjectError::Fatal)?;
        }
        enqueue.send(instance).map_err(|_| ObjectError::Fatal)?;

        Ok(Self {
            enqueue,
            dequeue,
            items,
            constructor: None,
        })
    }
}

impl<O: 'static> Pool<O> {
    pub fn with_constructor(
        items: usize,
        constructor: impl Fn() -> O + Send + Sync + 'static,
    ) -> Self {
        let (enqueue, dequeue) = mpsc::bounded(items);

        for _ in 0..items {
            enqueue.send(constructor()).unwrap();
        }

        Self {
            enqueue,
            dequeue,
            items,
            constructor: Some(Arc::new(constructor)),
        }
    }

    pub fn lease(&self) -> Result<PoolRef<O>> {
        if self.items == 0 {
            Ok(PoolRef {
                instance: Some(self.constructor.as_ref().unwrap()()),
                enqueue: None,
            })
        } else {
            let instance = Some(self.dequeue.recv().map_err(|_| ObjectError::Fatal)?);
            Ok(PoolRef {
                enqueue: Some(self.enqueue.clone()),
                instance,
            })
        }
    }

    pub fn count(&self) -> usize {
        self.items
    }
}

pub struct PoolRef<O> {
    enqueue: Option<mpsc::Sender<O>>,
    instance: Option<O>,
}

impl<O> Drop for PoolRef<O> {
    fn drop(&mut self) {
        self.enqueue
            .take()
            .map(|e| e.send(self.instance.take().unwrap()));
    }
}

impl<O> Deref for PoolRef<O> {
    type Target = O;

    fn deref(&self) -> &Self::Target {
        self.instance.as_ref().unwrap()
    }
}

impl<O> DerefMut for PoolRef<O> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.instance.as_mut().unwrap()
    }
}

impl<O> AsRef<O> for PoolRef<O> {
    fn as_ref(&self) -> &O {
        self.instance.as_ref().unwrap()
    }
}

impl<O> AsMut<O> for PoolRef<O> {
    fn as_mut(&mut self) -> &mut O {
        self.instance.as_mut().unwrap()
    }
}

impl<O> From<O> for PoolRef<O> {
    fn from(instance: O) -> Self {
        Self {
            instance: Some(instance),
            enqueue: None,
        }
    }
}
