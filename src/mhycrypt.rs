use rand_mt::Mt64;

pub fn mhy_xor(data: &mut [u8], key: &[u8])
{
    for (i, e) in data.iter_mut().enumerate() {
        *e ^= key[i % key.len()];
    }
}

pub fn mhy_generate_key(key: &mut [u8], seed: u64, legacy: bool)
{
    assert!(key.len() % 8 == 0);

    let mut mt = Mt64::new(seed);

    if !legacy {
        let seed = mt.next_u64();
        mt.reseed(seed);
        mt.next_u64();
    }

    // u64.to_be_bytes() or u64.to_le_bytes() ?
    for i in 0..key.len()/8 {
        let bytes = mt.next_u64().to_be_bytes();

        for (j, e) in bytes.iter().enumerate() {
            key[i*8 + j] = *e;
        }
    }
}
