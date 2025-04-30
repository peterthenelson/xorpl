
pub fn add<const N: usize>(reg: &mut [i32; N], a_x: usize, a_y: usize, b_x: usize, b_y: usize, c_x: usize, c_y: usize) {
    reg[c_x % N] = (
        (reg[a_x % N] ^ reg[a_y % N]) + (reg[b_x % N] ^ reg[b_y % N])
    ) ^ reg[c_y % N];
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_add() {
        let mut reg = [0; 16];
        reg[0] = 0x7ABC1234 ^ 222;
        reg[1] = 0x7ABC1234;
        reg[2] = 0x1234ABCD ^ 333;
        reg[3] = 0x1234ABCD;
        reg[4] = 0x1337BEEF ^ 100;
        reg[5] = 0x1337BEEF;
        println!("Before: {:?}", reg);
        add(&mut reg, 0, 1, 2, 3, 4, 5);
        println!("After:  {:?}", reg);
        assert_eq!(reg[4], 0x1337BEEF ^ 555);
    }
}