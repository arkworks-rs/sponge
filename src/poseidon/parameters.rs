use ark_ff::PrimeField;

/// Parameters describing a Poseidon instance.
#[derive(Clone, Debug)]
pub struct Parameters<F: PrimeField> {
    /// Number of rounds in a full-round operation.
    pub full_rounds: usize,
    /// Number of rounds in a partial-round operation.
    pub partial_rounds: usize,
    /// Exponent used in S-boxes.
    pub alpha: u64,
    /// Additive Round keys. These are added before each MDS matrix application to make it an affine shift.
    /// They are indexed by `ark[round_num][state_element_index]`
    pub ark: Vec<Vec<F>>,
    /// Maximally Distance Separating (MDS) Matrix.
    pub mds: Vec<Vec<F>>,
    /// The rate (in terms of number of field elements).
    /// See [On the Indifferentiability of the Sponge Construction](https://iacr.org/archive/eurocrypt2008/49650180/49650180.pdf)
    /// for more details on the rate and capacity of a sponge.
    pub rate: usize,
    /// The capacity (in terms of number of field elements).
    pub capacity: usize,
}

impl<F: PrimeField> Parameters<F> {
    /// Initialize the parameter for Poseidon Sponge.
    pub fn new(
        full_rounds: usize,
        partial_rounds: usize,
        alpha: u64,
        mds: Vec<Vec<F>>,
        ark: Vec<Vec<F>>,
        rate: usize,
        capacity: usize,
    ) -> Self {
        assert_eq!(ark.len(), full_rounds + partial_rounds);
        for item in &ark {
            assert_eq!(item.len(), rate + capacity);
        }
        assert_eq!(mds.len(), rate + capacity);
        for item in &mds {
            assert_eq!(item.len(), rate + capacity);
        }
        Self {
            full_rounds,
            partial_rounds,
            alpha,
            mds,
            ark,
            rate,
            capacity,
        }
    }
}
