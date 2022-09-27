//! Gadget that verifies a recursive proof.

use std::marker::PhantomData;

use halo2_gadgets::endoscale::EndoscaleInstructions;
use halo2_proofs::{
    arithmetic::CurveAffine,
    circuit::{AssignedCell, Layouter, Value},
    pasta::group::ff::PrimeFieldBits,
    plonk::{Error, VerifyingKey},
    transcript::{EncodedChallenge, TranscriptRead},
};

pub mod transcript;
use transcript::{Transcript, TranscriptInstructions};

struct Verifier<C, E, EndoscaleChip, TranscriptChip, TR>
where
    C: CurveAffine,
    C::Base: PrimeFieldBits,
    E: EncodedChallenge<C>,
    EndoscaleChip: EndoscaleInstructions<C>,
    TranscriptChip: TranscriptInstructions<C>,
    TR: TranscriptRead<C, E> + Clone,
{
    vk: VerifyingKey<C>,
    transcript: Transcript<C, TranscriptChip>,
    endoscale_chip: EndoscaleChip,
    fixed_bases: Vec<EndoscaleChip::FixedBases>,
    _marker: PhantomData<(E, TR)>,
}

impl<
        C: CurveAffine,
        E: EncodedChallenge<C>,
        EndoscaleChip: EndoscaleInstructions<C>,
        TranscriptChip: TranscriptInstructions<C>,
        TR: TranscriptRead<C, E> + Clone,
    > Verifier<C, E, EndoscaleChip, TranscriptChip, TR>
where
    C::Base: PrimeFieldBits,
{
    pub fn new(
        vk: VerifyingKey<C>,
        transcript_chip: TranscriptChip,
        endoscale_chip: EndoscaleChip,
        fixed_bases: Vec<EndoscaleChip::FixedBases>,
    ) -> Self {
        Self {
            vk,
            transcript: Transcript::new(transcript_chip),
            endoscale_chip,
            fixed_bases,
            _marker: PhantomData,
        }
    }

    pub fn verify_proof(
        &mut self,
        mut layouter: impl Layouter<C::Base>,
        proof: Value<TR>,
        instances: &[&[&[Value<bool>]]],
    ) -> Result<AssignedCell<bool, C::Base>, Error> {
        // Check that instances matches the expected number of instance columns
        if instances.len() != self.vk.cs().num_instance_columns() {
            return Err(Error::InvalidInstances);
        }

        let mut instance_commitments = vec![];
        for column in instances.iter() {
            let mut column_vec = vec![];
            for instance in column.iter() {
                let instance = self.endoscale_chip
                .witness_bitstring(&mut layouter, instance, false)?;
                let commitment = self.endoscale_chip.endoscale_fixed_base(&mut layouter, instance, self.fixed_bases.clone())?;
                column_vec.push(commitment);
            }
            instance_commitments.push(column_vec);
        }

        // Hash verification key into transcript
        self.transcript.common_scalar(
            layouter.namespace(|| "vk"),
            Value::known(self.vk.transcript_repr()),
        )?;

        let cs = self.vk.cs();
        for _ in 0..cs.num_advice_columns() {
            let advice = proof.clone().map(|mut p| p.read_point().unwrap());
            self.transcript
                .common_point(layouter.namespace(|| ""), advice)?;
        }

        todo!()
    }
}
