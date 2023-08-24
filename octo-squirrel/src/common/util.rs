use rand::RngCore;

pub struct Dice;

impl Dice {
    pub fn roll_bytes(len: usize) -> Vec<u8> {
        let mut dest = vec![0; len];
        rand::thread_rng().fill_bytes(&mut dest);
        dest
    }
}

pub struct FNV;

impl FNV {
    pub fn fnv1a32(data: &[u8]) -> u32 {
        let mut hash: u32 = 2166136261; // offset basis
        for b in data {
            hash ^= *b as u32;
            hash = hash.wrapping_mul(16777619); // prime
        }
        hash
    }
}

#[test]
fn test_fnv1a32() {
    let data = b"fn bubble_sort<T: Ord>(arr: &mut [T]) {let mut swapped = true;while swapped {swapped = false;for i in 1..arr.len() {if arr[i - 1] > arr[i] {arr.swap(i - 1, i);swapped = true;}}}}";
    assert_eq!(3156541508, FNV::fnv1a32(data));
}
