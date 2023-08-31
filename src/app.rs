use std::marker::PhantomData;

use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{AssignedCell, Layouter, Value},
    plonk::{Advice, Assigned, Column, ConstraintSystem, Constraints, Error, Expression, Selector},
    poly::Rotation,
};

///This circuit checks whether the sum of the two witness values in the cell is equal to the other given value.
///
///        value  value   |    q_sum_check
///       ------------------------------
///          a      b   |          1
///

#[derive(Debug, Clone)]
/// constrained value of SumCheckConfig.
struct SumConstrained<F: FieldExt, const SUM: usize>(
    AssignedCell<Assigned<F>, F>,
    AssignedCell<Assigned<F>, F>,
);

#[derive(Debug, Clone)]
struct SumCheckConfig<F: FieldExt, const SUM: usize> {
    a: Column<Advice>,
    b: Column<Advice>,
    q_sum_check: Selector,
    _marker: PhantomData<F>,
}

impl<F: FieldExt, const SUM: usize> SumCheckConfig<F, SUM> {
    pub fn configure(meta: &mut ConstraintSystem<F>, a: Column<Advice>, b: Column<Advice>) -> Self {
        let q_sum_check = meta.selector();

        meta.create_gate("sum check", |meta| {
            //        value     |    q_sum_check
            //       ------------------------------
            //          v       |         1

            let q: Expression<F> = meta.query_selector(q_sum_check);
            let a = meta.query_advice(a, Rotation::cur());
            let b = meta.query_advice(b, Rotation::cur());

            // Given a sum R and two value v, returns the expression
            // If equal, a+b-c should=0
            let sum_check = |sum: usize, a: Expression<F>, b: Expression<F>| {
                a + b - Expression::Constant(F::from(sum as u64))
            };
            let ret = sum_check(SUM, a, b);
            Constraints::with_selector(q, [("sum check", ret)])
        });

        Self {
            q_sum_check,
            a,
            b,
            _marker: PhantomData,
        }
    }

    pub fn assign(
        &self,
        mut layouter: impl Layouter<F>,
        a: Value<Assigned<F>>,
        b: Value<Assigned<F>>,
    ) -> Result<SumConstrained<F, SUM>, Error> {
        layouter.assign_region(
            || "Assign value",
            |mut region| {
                let offset = 0;
                // Enable q_sum_check
                self.q_sum_check.enable(&mut region, offset)?;

                // Assign value
                let a_cell = region.assign_advice(|| "a", self.a, offset, || a)?;
                let b_cell = region.assign_advice(|| "b", self.b, offset, || b)?;
                let cons = SumConstrained(a_cell, b_cell);
                Ok(cons)
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use halo2_proofs::{circuit::floor_planner::V1, dev::MockProver, pasta::Fp, plonk::Circuit};

    use super::*;

    #[derive(Default)]
    struct SumCircuit<F: FieldExt, const SUM: usize> {
        a: Value<Assigned<F>>,
        b: Value<Assigned<F>>,
    }

    impl<F: FieldExt, const SUM: usize> Circuit<F> for SumCircuit<F, SUM> {
        type Config = SumCheckConfig<F, SUM>;
        type FloorPlanner = V1;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            let a = meta.advice_column();
            let b = meta.advice_column();
            SumCheckConfig::configure(meta, a, b)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            config.assign(layouter.namespace(|| "Assign value"), self.a, self.b)?;

            Ok(())
        }
    }

    #[test]
    fn test_sum_check() {
        let k = 4;
        const SUM: usize = 15; // 3-bit value

        {
            let circuit = SumCircuit::<Fp, SUM> {
                a: Value::known(Fp::from(12 as u64).into()),
                b: Value::known(Fp::from(3 as u64).into()),
            };
            let prover = MockProver::run(k, &circuit, vec![]).unwrap();
            assert_eq!(prover.verify().is_ok(), true);
        }
    }

    #[cfg(feature = "dev-graph")]
    #[test]
    fn print_sum_check() {
        use plotters::prelude::*;

        let root = BitMapBackend::new("sum-check-1-layout.png", (1024, 3096)).into_drawing_area();
        root.fill(&WHITE).unwrap();
        let root = root
            .titled("Sum Check 1 Layout", ("sans-serif", 60))
            .unwrap();

        let circuit = SumCircuit::<Fp, 8> {
            a: Value::unknown(),
            b: Value::unknown(),
        };
        halo2_proofs::dev::CircuitLayout::default()
            .render(3, &circuit, &root)
            .unwrap();
    }
}
