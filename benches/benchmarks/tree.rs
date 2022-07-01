use infinitree::{
    backends::test::InMemoryBackend, fields::Serialized, keys::UsernamePassword, Index, Infinitree,
};

use criterion::{criterion_group, Criterion};

criterion_group!(tree, empty_commit, empty_open, load_1_value);

#[derive(Index, Default, Clone)]
pub struct Measurements {
    last_time: Serialized<usize>,
}

fn empty_commit(c: &mut Criterion) {
    c.bench_function("commit empty in-memory", |b| {
        let mut tree = Infinitree::<Measurements>::empty(
            InMemoryBackend::shared(),
            UsernamePassword::with_credentials(
                "username".to_string().into(),
                "password".to_string().into(),
            )
            .unwrap(),
        )
        .unwrap();

        b.iter(|| {
            tree.commit("empty commit yay").unwrap();
        });
    });
}

fn empty_open(c: &mut Criterion) {
    c.bench_function("open empty tree", |b| {
        let backend = {
            let b = InMemoryBackend::shared();
            let mut tree = Infinitree::<Measurements>::empty(
                b.clone(),
                UsernamePassword::with_credentials(
                    "username".to_string().into(),
                    "password".to_string().into(),
                )
                .unwrap(),
            )
            .unwrap();
            tree.commit("empty commit yay").unwrap();

            b
        };

        b.iter(|| {
            let _ = Infinitree::<Measurements>::open(
                backend.clone(),
                UsernamePassword::with_credentials(
                    "username".to_string().into(),
                    "password".to_string().into(),
                )
                .unwrap(),
            )
            .unwrap();
        });
    });
}

fn load_1_value(c: &mut Criterion) {
    c.bench_function("load usize as index", |b| {
        let mut tree = Infinitree::<Measurements>::empty(
            InMemoryBackend::shared(),
            UsernamePassword::with_credentials(
                "username".to_string().into(),
                "password".to_string().into(),
            )
            .unwrap(),
        )
        .unwrap();
        tree.commit("empty commit yay").unwrap();

        b.iter(|| tree.load_all().unwrap());
    });
}
