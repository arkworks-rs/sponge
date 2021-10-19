#[cfg(feature = "r1cs")]
pub mod constraints;
pub mod traits;

mod grain_lfsr;
mod parameters;
mod sponge;
mod state;

pub use parameters::Parameters;
pub use sponge::Sponge;
pub use state::State;
pub use traits::*;

#[cfg(test)]
mod tests;
