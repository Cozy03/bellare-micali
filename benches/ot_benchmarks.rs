use bellare_micali::{Message, OTProtocol};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use rand::rngs::OsRng;
use rayon::prelude::*;
use std::time::Duration;

fn bench_ot_protocol(c: &mut Criterion) {
    let mut group = c.benchmark_group("OT Protocol");
    group.measurement_time(Duration::from_secs(10));

    // Benchmark different message sizes
    for size in [16, 32, 64, 128, 256, 512, 1024, 2048, 4096].iter() {
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::new("message_size", size), size, |b, &size| {
            let mut rng = OsRng;
            let msg0 = Message::new(vec![0u8; size]);
            let msg1 = Message::new(vec![1u8; size]);

            b.iter(|| {
                let sender = OTProtocol::new_sender(&mut rng);
                let receiver = OTProtocol::new_receiver(&mut rng, black_box(true), sender.c);
                let (pk0, pk1) = OTProtocol::receiver_generate_keys(&receiver, sender.c);

                let (c0, c1) =
                    OTProtocol::sender_encrypt(&mut rng, &sender, pk0, pk1, &msg0, &msg1).unwrap();

                OTProtocol::receiver_decrypt(&receiver, &c0, &c1).unwrap()
            });
        });
    }

    group.finish();
}

fn bench_batch_processing(c: &mut Criterion) {
    let mut group = c.benchmark_group("Batch Processing");
    group.measurement_time(Duration::from_secs(10));

    let batch_sizes = [1, 10, 50, 100];
    let msg_size = 1024;

    for &batch_size in batch_sizes.iter() {
        group.throughput(Throughput::Elements(batch_size as u64));
        group.bench_with_input(
            BenchmarkId::new("batch_size", batch_size),
            &batch_size,
            |b, &size| {
                let msgs0: Vec<_> = (0..size)
                    .map(|_| Message::new(vec![0u8; msg_size]))
                    .collect();
                let msgs1: Vec<_> = (0..size)
                    .map(|_| Message::new(vec![1u8; msg_size]))
                    .collect();

                b.iter(|| {
                    // Create sender with its own RNG
                    let mut sender_rng = OsRng;
                    let sender = OTProtocol::new_sender(&mut sender_rng);

                    let results: Vec<_> = (0..size)
                        .into_par_iter()
                        .map(|i| {
                            // Create new RNG for each thread
                            let mut thread_rng = OsRng;
                            let receiver =
                                OTProtocol::new_receiver(&mut thread_rng, true, sender.c);
                            let (pk0, pk1) =
                                OTProtocol::receiver_generate_keys(&receiver, sender.c);

                            let (c0, c1) = OTProtocol::sender_encrypt(
                                &mut thread_rng,
                                &sender,
                                pk0,
                                pk1,
                                &msgs0[i],
                                &msgs1[i],
                            )
                            .unwrap();

                            OTProtocol::receiver_decrypt(&receiver, &c0, &c1).unwrap()
                        })
                        .collect();

                    results
                });
            },
        );
    }

    group.finish();
}

fn bench_individual_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("Individual Operations");
    let mut rng = OsRng;

    group.bench_function("sender_init", |b| {
        b.iter(|| {
            let mut rng = OsRng;
            OTProtocol::new_sender(&mut rng)
        });
    });

    let sender = OTProtocol::new_sender(&mut rng);
    group.bench_function("receiver_init", |b| {
        b.iter(|| {
            let mut rng = OsRng;
            OTProtocol::new_receiver(&mut rng, black_box(true), sender.c)
        });
    });

    let receiver = OTProtocol::new_receiver(&mut rng, true, sender.c);
    group.bench_function("key_generation", |b| {
        b.iter(|| OTProtocol::receiver_generate_keys(&receiver, sender.c));
    });

    let (pk0, pk1) = OTProtocol::receiver_generate_keys(&receiver, sender.c);
    let msg0 = Message::new(vec![0u8; 128]);
    let msg1 = Message::new(vec![1u8; 128]);

    group.bench_function("encryption", |b| {
        b.iter(|| {
            let mut rng = OsRng;
            OTProtocol::sender_encrypt(&mut rng, &sender, pk0, pk1, &msg0, &msg1).unwrap()
        });
    });

    let (c0, c1) = OTProtocol::sender_encrypt(&mut rng, &sender, pk0, pk1, &msg0, &msg1).unwrap();

    group.bench_function("decryption", |b| {
        b.iter(|| OTProtocol::receiver_decrypt(&receiver, &c0, &c1).unwrap());
    });

    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .sample_size(100)
        .measurement_time(Duration::from_secs(10));
    targets = bench_ot_protocol, bench_batch_processing, bench_individual_operations
}
criterion_main!(benches);
