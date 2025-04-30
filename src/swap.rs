use rand::Rng;

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub struct XMatrix<const N: usize>([[u8; N]; N]);

impl<const N: usize> XMatrix<N> {
    pub fn new() -> Self {
        Self([[0; N]; N])
    }

    pub fn identity() -> Self {
        let mut x = Self::new();
        for i in 0..N {
            x.0[i][i] = 1;
        }
        x
    }

    pub fn get(&self, i: usize, j: usize) -> u8 {
        assert!(i < N && j < N, "Index out of bounds");
        self.0[i][j]
    }

    pub fn set(&mut self, i: usize, j: usize, value: u8) {
        assert!(i < N && j < N, "Index out of bounds");
        assert!(value <= 1, "Value must be 0 or 1");
        self.0[i][j] = value;
    }

    pub fn parse(s: &str) -> Result<Self, &'static str> {
        let mut x = Self::new();
        for (i, line) in s.lines().enumerate() {
            for (j, c) in line.chars().enumerate() {
                if c == '1' {
                    x.0[i][j] = 1;
                } else if c == '0' {
                    x.0[i][j] = 0;
                } else {
                    return Err("Invalid character in input string");
                }
            }
        }
        Ok(x)
    }

    pub fn serialize(&self) -> String {
        let mut s = String::new();
        for i in 0..N {
            for j in 0..N {
                s.push(if self.0[i][j] == 1 { '1' } else { '0' });
            }
            s.push('\n');
        }
        s
    }

    pub fn rand() -> Self {
        let mut rng = rand::rng();
        let mut x = Self::new();
        for i in 0..N {
            for j in 0..N {
                x.0[i][j] = rng.random_range(0..=1);
            }
        }
        x
    }

    /// Swaps rows `row_a` and `row_b` in the matrix.
    pub fn swap_rows(&mut self, row_a: usize, row_b: usize) {
        assert!(row_a < N && row_b < N, "Row index out of bounds");
        for j in 0..N {
            let temp = self.0[row_a][j];
            self.0[row_a][j] = self.0[row_b][j];
            self.0[row_b][j] = temp;
        }
    }

    /// Sets row `row_a` equal to the (xor) sum of itself and row `row_b`.
    pub fn add_row(&mut self, row_a: usize, row_b: usize) {
        assert!(row_a < N && row_b < N, "Row index out of bounds");
        for j in 0..N {
            self.0[row_a][j] ^= self.0[row_b][j];
        }
    }

    pub fn row_echelon(&mut self) {
        let mut lead: usize = 0;
        for c in 0..N {
            let mut pivot = None;
            for r in lead..N {
                if self.0[r][c] != 0 {
                    pivot = Some(r);
                    break;
                }
            }
            match pivot {
                None => { continue; },
                Some(p) => {
                    if p != lead {
                        self.swap_rows(lead, p);
                    }
                    for r2 in lead + 1..N {
                        if self.0[r2][c] != 0 {
                            self.add_row(r2, lead);
                        }
                    }
                    lead += 1;
                }
            }
        }
    }

    pub fn rank(&self) -> usize {
        let mut x = self.clone();
        x.row_echelon();
        let mut k = 0;
        for i in 0..N {
            if x.0[i].iter().any(|&x| x != 0) {
                k += 1;
            }
        }
        k
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_set_get() {
        let mut x = XMatrix::<3>::new();
        x.set(0, 0, 1);
        x.set(1, 1, 1);
        x.set(1, 1, 0);
        assert_eq!(x.get(0, 0), 1);
        assert_eq!(x.get(1, 1), 0);
        assert_eq!(x.get(2, 2), 0);
    }

    #[test]
    fn test_identity() {
        let x = XMatrix::<3>::identity();
        assert_eq!(x.get(0, 0), 1);
        assert_eq!(x.get(1, 1), 1);
        assert_eq!(x.get(2, 2), 1);
        assert_eq!(x.get(0, 1), 0);
        assert_eq!(x.get(1, 0), 0);
        assert_eq!(x.get(2, 0), 0);
    }

    #[test]
    fn test_parse_serialize() {
        let input = "110\n001\n000\n";
        assert_eq!(XMatrix::<3>::parse(input).unwrap().serialize(), input);
    }

    #[test]
    fn test_swap_rows() {
        let mut x = XMatrix::<3>::parse("110\n001\n000\n").unwrap();
        x.swap_rows(0, 1);
        assert_eq!(x.serialize(), "001\n110\n000\n");
    }

    #[test]
    fn test_add_rows() {
        let mut x = XMatrix::<3>::parse("110\n001\n000\n").unwrap();
        x.add_row(0, 1);
        assert_eq!(x.serialize(), "111\n001\n000\n");
    }

    #[test]
    fn test_row_echelon() {
        let mut x = XMatrix::<3>::parse("110\n101\n100\n").unwrap();
        x.row_echelon();
        assert_eq!(x.serialize(), "110\n011\n001\n");
        let mut y = XMatrix::<3>::parse("010\n010\n010\n").unwrap();
        y.row_echelon();
        assert_eq!(y.serialize(), "010\n000\n000\n");
    }

    #[test]
    fn test_rank() {
        let x = XMatrix::<3>::parse("110\n101\n100\n").unwrap();
        assert_eq!(x.rank(), 3);
        let y = XMatrix::<3>::parse("110\n101\n011\n").unwrap();
        assert_eq!(y.rank(), 2);
        let z = XMatrix::<3>::parse("010\n010\n010\n").unwrap();
        assert_eq!(z.rank(), 1);
    }

    #[ignore]
    #[test]
    fn test_random_walk() {
        println!("{}", std::env::args().collect::<String>());
        let mut x = XMatrix::<3>::identity();
        let mut seen: HashSet<XMatrix<3>> = HashSet::new();
        seen.insert(x);
        let mut rng = rand::rng();
        for _ in 0..100 {
            let mut y = x.clone();
            let row_a = rng.random_range(0..3);
            let row_b = rng.random_range(0..3);
            y.add_row(row_a, row_b);
            if y.rank() != 3 {
                println!("Reject update:\n{}", y.serialize());
                continue;
            }
            println!("Accept update:\n{}", y.serialize());
            x = y;
            seen.insert(y);
        }
    }
}