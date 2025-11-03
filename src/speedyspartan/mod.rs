pub mod folding;
pub mod plonkish;
pub mod rerandomization;
pub mod snark;
pub mod sumchecks;
mod utils;
const ADDR_DIM: usize = 3;
pub mod circuit;
pub mod pcd;

pub const PLONKISH_N_ROUNDS: usize = 18;
pub const PLONKISH_DEGREE: usize = 4;
pub const ADDR_N_ROUNDS: usize = 18;
pub const ADDR_DEGREE: usize = 4;
pub const RERAND_DEGREE: usize = 2;
