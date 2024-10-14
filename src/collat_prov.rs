use ra_tls::collateral_prov::CollateralProvider;
use ra_verify::types::quote::SgxQuote;
use std::io;

use crate::{get_collateral, CaIdentifier};

/// Provides the SGX collateral from the given quote.
pub struct ExternalCollateralProvider {
    pccs_url: String,
}

impl ExternalCollateralProvider {
    pub fn new(pccs_url: String) -> Self {
        Self { pccs_url }
    }
}

impl CollateralProvider for ExternalCollateralProvider {
    fn get_collateral(&self, quote: Vec<u8>) -> std::io::Result<Vec<u8>> {
        let mut quote_bytes: &[u8] = &quote;
        let quote = SgxQuote::read(&mut quote_bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{e:?}")))?;
        let collat = get_collateral(
            &self.pccs_url,
            quote.support.pck_extension.fmspc,
            CaIdentifier::Processor,
        )
        .map(|c| serde_json::to_vec(&c).unwrap())
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("{e:?}")))?;
        Ok(serde_json::to_vec(&collat).unwrap())
    }
}
