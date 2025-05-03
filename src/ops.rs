pub fn xop<const N: usize, F: Fn(i32, i32) -> i32>(reg: &mut [i32; N], a_x: usize, a_y: usize, b_x: usize, b_y: usize, c_x: usize, c_y: usize, f: F) {
    reg[c_x % N] = f(reg[a_x % N] ^ reg[a_y % N], reg[b_x % N] ^ reg[b_y % N]) ^ reg[c_y % N];
}

pub fn add<const N: usize>(reg: &mut [i32; N], a_x: usize, a_y: usize, b_x: usize, b_y: usize, c_x: usize, c_y: usize) {
    xop(reg, a_x, a_y, b_x, b_y, c_x, c_y, |x, y| x + y);
}

pub fn sub<const N: usize>(reg: &mut [i32; N], a_x: usize, a_y: usize, b_x: usize, b_y: usize, c_x: usize, c_y: usize) {
    xop(reg, a_x, a_y, b_x, b_y, c_x, c_y, |x, y| x - y);
}

pub fn mul<const N: usize>(reg: &mut [i32; N], a_x: usize, a_y: usize, b_x: usize, b_y: usize, c_x: usize, c_y: usize) {
    xop(reg, a_x, a_y, b_x, b_y, c_x, c_y, |x, y| x * y);
}

pub fn div<const N: usize>(reg: &mut [i32; N], a_x: usize, a_y: usize, b_x: usize, b_y: usize, c_x: usize, c_y: usize) {
    xop(reg, a_x, a_y, b_x, b_y, c_x, c_y, |x, y| x / y);
}

pub fn swap<const N: usize>(reg: &mut [i32; N], x: usize, y: usize) {
    (reg[x % N], reg[y % N]) = (reg[y % N], reg[x % N]);
}

pub fn move_reg<const N: usize>(reg: &mut [i32; N], x: usize, y: usize) {
    reg[y % N] = reg[x % N];
}

#[cfg(test)]
mod test {
    use super::*;

    fn setup_reg<const N: usize>(x: i32, y: i32, z: i32) -> [i32; N] {
        assert!(N >= 6, "Register array must be at least 6 elements long");
        let mut reg = [0; N];
        reg[0] = 0x7ABC1234 ^ x;
        reg[1] = 0x7ABC1234;
        reg[2] = 0x1234ABCD ^ y;
        reg[3] = 0x1234ABCD;
        reg[4] = 0x1337BEEF ^ z;
        reg[5] = 0x1337BEEF;
        reg
    }

    #[test]
    fn test_add() {
        let mut reg: [i32; 8] = setup_reg(222, 333, 100);
        add(&mut reg, 0, 1, 2, 3, 4, 5);
        assert_eq!(reg[4], 0x1337BEEF ^ 555);
    }

    #[test]
    fn test_sub() {
        let mut reg: [i32; 8] = setup_reg(222, 333, 100);
        sub(&mut reg, 0, 1, 2, 3, 4, 5);
        assert_eq!(reg[4], 0x1337BEEF ^ -111);
    }

    #[test]
    fn test_mul() {
        let mut reg: [i32; 8] = setup_reg(222, 333, 100);
        mul(&mut reg, 0, 1, 2, 3, 4, 5);
        assert_eq!(reg[4], 0x1337BEEF ^ (222 * 333));
    }

    #[test]
    fn test_div() {
        let mut reg: [i32; 8] = setup_reg(222, 333, 100);
        div(&mut reg, 0, 1, 2, 3, 4, 5);
        assert_eq!(reg[4], 0x1337BEEF ^ (222 / 333));
    }

    #[test]
    fn test_swap() {
        let mut reg: [i32; 8] = setup_reg(222, 333, 100);
        swap(&mut reg, 0, 1);
        assert_eq!(reg[0], 0x7ABC1234);
        assert_eq!(reg[1], 0x7ABC1234 ^ 222);
    }

    #[test]
    fn test_move_reg() {
        let mut reg: [i32; 8] = setup_reg(222, 333, 100);
        move_reg(&mut reg, 0, 1);
        assert_eq!(reg[0], 0x7ABC1234 ^ 222);
        assert_eq!(reg[1], 0x7ABC1234 ^ 222);
    }
}