use rand::Rng;

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub struct XMatrix<const R: usize, const C: usize>([[u8; C]; R]);

// Functions for square matrices specifically
impl <const N: usize> XMatrix<N, N> {
    pub fn identity() -> Self {
        let mut x = Self::new();
        for i in 0..N {
            x.0[i][i] = 1;
        }
        x
    }
}

pub enum XMatrixIterKind {
    Row,
    Col,
    Diagonal,
    Values,
}

pub struct XMatrixIter<'a, const R: usize, const C: usize> {
    matrix: &'a XMatrix<R, C>,
    kind: XMatrixIterKind,
    row: usize,
    col: usize,
}

impl <'a, const R: usize, const C: usize> Iterator for XMatrixIter<'a, R, C> {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        match self.kind {
            XMatrixIterKind::Row => {
                if self.col < C {
                    let value = self.matrix.0[self.row][self.col];
                    self.col += 1;
                    Some(value)
                } else {
                    None
                }
            },
            XMatrixIterKind::Col => {
                if self.row < R {
                    let value = self.matrix.0[self.row][self.col];
                    self.row += 1;
                    Some(value)
                } else {
                    None
                }
            },
            XMatrixIterKind::Diagonal => {
                if self.row < R && self.col < C {
                    let value = self.matrix.0[self.row][self.col];
                    self.row += 1;
                    self.col += 1;
                    Some(value)
                } else {
                    None
                }
            },
            XMatrixIterKind::Values => {
                if self.row < R && self.col < C {
                    let value = self.matrix.0[self.row][self.col];
                    self.col += 1;
                    if self.col == C {
                        self.col = 0;
                        self.row += 1;
                    }
                    Some(value)
                } else {
                    None
                }
            },
        }
    }
}

// Functions for general rectangular matrices
impl<const R: usize, const C: usize> XMatrix<R, C> {
    pub fn new() -> Self {
        Self([[0; C]; R])
    }

    pub fn get(&self, r: usize, c: usize) -> u8 {
        assert!(r < R && c < C, "Index out of bounds");
        self.0[r][c]
    }

    pub fn set(&mut self, r: usize, c: usize, value: u8) {
        assert!(r < R && c < C, "Index out of bounds");
        assert!(value <= 1, "Value must be 0 or 1");
        self.0[r][c] = value;
    }

    pub fn row(&self, r: usize) -> XMatrixIter<R, C> {
        assert!(r < R, "Row index out of bounds");
        XMatrixIter {
            matrix: self,
            kind: XMatrixIterKind::Row,
            row: r,
            col: 0,
        }
    }

    pub fn col(&self, c: usize) -> XMatrixIter<R, C> {
        assert!(c < C, "Col index out of bounds");
        XMatrixIter {
            matrix: self,
            kind: XMatrixIterKind::Col,
            row: 0,
            col: c,
        }
    }

    pub fn diagonal(&self) -> XMatrixIter<R, C> {
        XMatrixIter {
            matrix: self,
            kind: XMatrixIterKind::Diagonal,
            row: 0,
            col: 0,
        }
    }

    pub fn values(&self) -> XMatrixIter<R, C> {
        XMatrixIter {
            matrix: self,
            kind: XMatrixIterKind::Values,
            row: 0,
            col: 0,
        }
    }

    pub fn parse(s: &str) -> Result<Self, &'static str> {
        let mut x = Self::new();
        for (i, line) in s.lines().enumerate() {
            if i >= R {
                return Err("Number of rows exceeds matrix size");
            }
            for (j, c) in line.chars().enumerate() {
                if j >= C {
                    return Err("Number of cols exceeds matrix size");
                }
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
        for i in 0..R {
            for j in 0..C {
                s.push(if self.0[i][j] == 1 { '1' } else { '0' });
            }
            s.push('\n');
        }
        s
    }

    pub fn rand() -> Self {
        let mut rng = rand::rng();
        let mut x = Self::new();
        for i in 0..R {
            for j in 0..C {
                x.0[i][j] = rng.random_range(0..=1);
            }
        }
        x
    }

    /// Swaps rows `row_a` and `row_b` in the matrix.
    pub fn swap_rows(&mut self, row_a: usize, row_b: usize) {
        assert!(row_a < R && row_b < R, "Row index out of bounds");
        for j in 0..C {
            (self.0[row_a][j], self.0[row_b][j]) = (self.0[row_b][j], self.0[row_a][j]);
        }
    }

    /// Sets row `row_a` equal to the (xor) sum of itself and row `row_b`.
    pub fn add_row(&mut self, row_a: usize, row_b: usize) {
        assert!(row_a < R && row_b < R, "Row index out of bounds");
        for j in 0..C {
            self.0[row_a][j] ^= self.0[row_b][j];
        }
    }

    pub fn row_echelon(&mut self) {
        let mut lead: usize = 0;
        for c in 0..(std::cmp::min(R, C)) {
            let mut pivot = None;
            for r in lead..R {
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
                    for r2 in lead + 1..R {
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
        for i in 0..R {
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

    #[test]
    fn test_set_get() {
        let mut x = XMatrix::<3, 3>::new();
        x.set(0, 0, 1);
        x.set(1, 1, 1);
        x.set(1, 1, 0);
        assert_eq!(x.get(0, 0), 1);
        assert_eq!(x.get(1, 1), 0);
        assert_eq!(x.get(2, 2), 0);
    }

    #[test]
    fn test_iterators() {
        let mut x = XMatrix::<3, 3>::new();
        x.set(0, 0, 1);
        x.set(0, 1, 1);
        x.set(1, 1, 1);
        x.set(1, 2, 1);
        assert_eq!(x.row(1).collect::<Vec<_>>(), &[0, 1, 1]);
        assert_eq!(x.col(1).collect::<Vec<_>>(), &[1, 1, 0]);
        assert_eq!(x.diagonal().collect::<Vec<_>>(), &[1, 1, 0]);
        assert_eq!(x.values().collect::<Vec<_>>(), &[1, 1, 0, 0, 1, 1, 0, 0, 0]);
    }

    #[test]
    fn test_identity() {
        let x = XMatrix::<3, 3>::identity();
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
        assert_eq!(XMatrix::<3, 3>::parse(input).unwrap().serialize(), input);
    }

    #[test]
    fn test_swap_rows() {
        let mut x = XMatrix::<3, 3>::parse("110\n001\n000\n").unwrap();
        x.swap_rows(0, 1);
        assert_eq!(x.serialize(), "001\n110\n000\n");
    }

    #[test]
    fn test_add_rows() {
        let mut x = XMatrix::<3, 3>::parse("110\n001\n000\n").unwrap();
        x.add_row(0, 1);
        assert_eq!(x.serialize(), "111\n001\n000\n");
    }

    #[test]
    fn test_swap_trick() {
        let mut x = XMatrix::<3, 3>::parse("110\n001\n000\n").unwrap();
        x.add_row(0, 1);
        x.add_row(1, 0);
        x.add_row(0, 1);
        assert_eq!(x.serialize(), "001\n110\n000\n");
    }

    #[test]
    fn test_row_echelon() {
        let mut x = XMatrix::<3, 3>::parse("110\n101\n100\n").unwrap();
        x.row_echelon();
        assert_eq!(x.serialize(), "110\n011\n001\n");
        let mut y = XMatrix::<3, 3>::parse("010\n010\n010\n").unwrap();
        y.row_echelon();
        assert_eq!(y.serialize(), "010\n000\n000\n");
        let mut z = XMatrix::<4, 3>::parse("111\n011\n001\n111\n").unwrap();
        z.row_echelon();
        assert_eq!(z.serialize(), "111\n011\n001\n000\n");
    }

    #[test]
    fn test_rank() {
        let x = XMatrix::<3, 3>::parse("110\n101\n100\n").unwrap();
        assert_eq!(x.rank(), 3);
        let y = XMatrix::<3, 3>::parse("110\n101\n011\n").unwrap();
        assert_eq!(y.rank(), 2);
        let z = XMatrix::<3, 3>::parse("010\n010\n010\n").unwrap();
        assert_eq!(z.rank(), 1);
    }
}