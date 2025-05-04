use xorpl::swap::XMatrix;
use rand::Rng;
use std::collections::HashSet;

/// Unpermutated layout for C/2 cipher-key pairs in R physical registers.
fn default_layout<const R: usize, const C: usize>() -> XMatrix<R, C> {
    assert!(R >= C, "R (num physical registers) must be at least C (num cipher/key registers)");
    assert!(C % 2 == 0, "C (num cipher/key registers) must be even");
    let mut x = XMatrix::<R, C>::new();
    for i in 0..C {
        x.set(i, i, 1);
    }
    x
}

/// Checks if any physical register contains a single cipher/key xor'd together.
fn has_plaintext<const R: usize, const C: usize>(x: &XMatrix<R, C>) -> bool {
    assert!(C % 2 == 0, "C (num cipher/key registers) must be even");
    let num_pairs = C / 2;
    for r in 0..R {
        if x.row(r).sum::<u8>() != 2 {
            continue;
        }
        for p in 0..num_pairs {
            if x.get(r, p * 2) == 1 && x.get(r, p * 2 + 1) == 1 {
                return true;
            }
        }
    }
    false
}

fn valid_end_state<const R: usize, const C: usize>(x: &XMatrix<R, C>) -> bool {
    assert!(C % 2 == 0, "C (num cipher/key registers) must be even");
    // A subset of rows form a permutation of the default layout's first C rows.
    let mut indicator_rows: [u8; C] = [0; C];
    for r in 0..R {
        let mut sum = 0;
        let mut first: usize = 0;
        for c in 0..C {
            if x.get(r, c) == 1 {
                sum += 1;
                if first == 0 {
                    first = c;
                }
            }
        }
        if sum == 1 {
            indicator_rows[first] = 1;
        }
    }
    indicator_rows.iter().all(|&x| x == 1)
}

fn neighbors<const R: usize, const C: usize>(x: &XMatrix<R, C>) -> Vec<XMatrix<R, C>> {
    let mut neighbors = Vec::new();
    for i in 0..R {
        for j in 0..R {
            if i == j {
                continue;
            }
            let mut y = x.clone();
            y.add_row(i, j);
            if y.rank() != x.rank() || has_plaintext(&y) {
                continue;
            }
            neighbors.push(y);
        }
    }
    neighbors
}

/// TODO: Redo this as a dfs thing?
pub fn main() {
    const R: usize = 8;
    const C: usize = 6;
    let mut x = default_layout::<R, C>();
    assert_eq!(x.rank(), C);
    assert!(valid_end_state(&x));
    let mut seen: HashSet<XMatrix<R, C>> = HashSet::new();
    let mut end_states: HashSet<XMatrix<R, C>> = HashSet::new();
    let mut rng = rand::rng();
    for _ in 0..10000000 {
        if !seen.contains(&x) && valid_end_state(&x) {
            println!("Reached valid end-state:\n{}", x.serialize());
            end_states.insert(x);
        }
        seen.insert(x);
        let candidates = neighbors(&x);
        if candidates.is_empty() {
            println!("Stuck!");
            break;
        }
        x = candidates[rng.random_range(0..candidates.len())];
    }
    println!("Num seen: {}; num end states: {}", seen.len(), end_states.len());
}