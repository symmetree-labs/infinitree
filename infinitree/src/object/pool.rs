use super::{ObjectError, Result};
use flume as mpsc;
use std::{
    num::NonZeroUsize,
    ops::{Deref, DerefMut},
    sync::Arc,
};

pub(crate) mod buffer;
pub(crate) mod reader;
pub(crate) mod writer;

pub struct Pool<O> {
    enqueue: mpsc::Sender<O>,
    dequeue: mpsc::Receiver<O>,
    count: usize,
    constructor: Option<Arc<dyn Fn() -> O + Send + Sync>>,
}

impl<O> Clone for Pool<O> {
    fn clone(&self) -> Self {
        Self {
            enqueue: self.enqueue.clone(),
            dequeue: self.dequeue.clone(),
            count: self.count,
            constructor: self.constructor.clone(),
        }
    }
}

impl<O: 'static + Clone> Pool<O> {
    pub fn new(items: NonZeroUsize, instance: O) -> Result<Self> {
        let count = items.get();
        let (enqueue, dequeue) = mpsc::bounded(count);

        for _ in 0..(count - 1) {
            enqueue
                .send(instance.clone())
                .map_err(|_| ObjectError::Fatal)?;
        }
        enqueue.send(instance).map_err(|_| ObjectError::Fatal)?;

        Ok(Self {
            enqueue,
            dequeue,
            count,
            constructor: None,
        })
    }
}

impl<O: 'static> Pool<O> {
    pub fn with_constructor(
        count: usize,
        constructor: impl Fn() -> O + Send + Sync + 'static,
    ) -> Self {
        let (enqueue, dequeue) = mpsc::bounded(count);

        for _ in 0..count {
            enqueue.send(constructor()).unwrap();
        }

        Self {
            enqueue,
            dequeue,
            count,
            constructor: Some(Arc::new(constructor)),
        }
    }

    pub fn lease(&self) -> Result<PoolRef<O>> {
        if self.count == 0 {
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
        self.count
    }
}

pub struct PoolRef<O> {
    enqueue: Option<mpsc::Sender<O>>,
    instance: Option<O>,
}

impl<O> Drop for PoolRef<O> {
    #[inline(always)]
    fn drop(&mut self) {
        self.enqueue
            .take()
            .map(|e| e.send(self.instance.take().unwrap()));
    }
}

impl<O> Deref for PoolRef<O> {
    type Target = O;

    #[inline(always)]
    fn deref(&self) -> &Self::Target {
        self.instance.as_ref().unwrap()
    }
}

impl<O> DerefMut for PoolRef<O> {
    #[inline(always)]
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.instance.as_mut().unwrap()
    }
}

impl<O> AsRef<O> for PoolRef<O> {
    #[inline(always)]
    fn as_ref(&self) -> &O {
        self.instance.as_ref().unwrap()
    }
}

impl<O> AsMut<O> for PoolRef<O> {
    #[inline(always)]
    fn as_mut(&mut self) -> &mut O {
        self.instance.as_mut().unwrap()
    }
}

impl<O> From<O> for PoolRef<O> {
    #[inline(always)]
    fn from(instance: O) -> Self {
        Self {
            instance: Some(instance),
            enqueue: None,
        }
    }
}
