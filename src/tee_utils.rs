use anyhow::Result;
use dcap_rs::{constants::{SGX_TEE_TYPE, TDX_TEE_TYPE}, types::collaterals::IntelCollateral};
use dcap_sp1_cli::{chain::pccs::{
    enclave_id::{get_enclave_identity, EnclaveIdType},
    fmspc_tcb::get_tcb_info,
    pcs::{get_certificate_by_id, IPCSDao::CA},
}, parser::get_pck_fmspc_and_issuer};

pub fn remove_prefix_if_found(h: &str) -> &str {
    h.trim_start_matches("0x")
}

// Helper function to get hex strings
pub fn to_hex_with_prefix(bytes: &[u8]) -> String {
    let hex_string: String = bytes.iter()
        .map(|b| format!("{:02x}", b))
        .collect();
    format!("0x{}", hex_string)
}

pub fn generate_input(quote: &[u8], collaterals: &[u8]) -> Vec<u8> {
    // get current time in seconds since epoch
    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let current_time_bytes = current_time.to_le_bytes();

    let quote_len = quote.len() as u32;
    let intel_collaterals_bytes_len = collaterals.len() as u32;
    let total_len = 8 + 4 + 4 + quote_len + intel_collaterals_bytes_len;

    let mut input = Vec::with_capacity(total_len as usize);
    input.extend_from_slice(&current_time_bytes);
    input.extend_from_slice(&quote_len.to_le_bytes());
    input.extend_from_slice(&intel_collaterals_bytes_len.to_le_bytes());
    input.extend_from_slice(&quote);
    input.extend_from_slice(&collaterals);

    input.to_owned()
}


pub async fn get_sp1_input(quote: Vec<u8>) -> Result<Vec<u8>> {

    // Step 1: Determine quote version and TEE type
    let quote_version = u16::from_le_bytes([quote[0], quote[1]]);
    let tee_type = u32::from_le_bytes([quote[4], quote[5], quote[6], quote[7]]);

    println!("Quote version: {}", quote_version);
    println!("TEE Type: {}", tee_type);

    if quote_version < 3 || quote_version > 4 {
        panic!("Unsupported quote version");
    }

    if tee_type != SGX_TEE_TYPE && tee_type != TDX_TEE_TYPE {
        panic!("Unsupported tee type");
    }

    // Step 2: Load collaterals
    println!("Quote read successfully. Begin fetching collaterals from the on-chain PCCS");

    let (root_ca, root_ca_crl) = get_certificate_by_id(CA::ROOT).await?;
    if root_ca.is_empty() || root_ca_crl.is_empty() {
        panic!("Intel SGX Root CA is missing");
    } else {
        println!("Fetched Intel SGX RootCA and CRL");
    }

    let (fmspc, pck_type, pck_issuer) =
        get_pck_fmspc_and_issuer(&quote, quote_version, tee_type);

    let tcb_type: u8;
    if tee_type == TDX_TEE_TYPE {
        tcb_type = 1;
    } else {
        tcb_type = 0;
    }
    let tcb_version: u32;
    if quote_version < 4 {
        tcb_version = 2
    } else {
        tcb_version = 3
    }
    let tcb_info = get_tcb_info(tcb_type, fmspc.as_str(), tcb_version).await?;

    println!("Fetched TCBInfo JSON for FMSPC: {}", fmspc);

    let qe_id_type: EnclaveIdType;
    if tee_type == TDX_TEE_TYPE {
        qe_id_type = EnclaveIdType::TDQE
    } else {
        qe_id_type = EnclaveIdType::QE
    }
    let qe_identity = get_enclave_identity(qe_id_type, quote_version as u32).await?;
    println!("Fetched QEIdentity JSON");

    let (signing_ca, _) = get_certificate_by_id(CA::SIGNING).await?;
    if signing_ca.is_empty() {
        panic!("Intel TCB Signing CA is missing");
    } else {
        println!("Fetched Intel TCB Signing CA");
    }

    let (_, pck_crl) = get_certificate_by_id(pck_type).await?;
    if pck_crl.is_empty() {
        panic!("CRL for {} is missing", pck_issuer);
    } else {
        println!("Fetched Intel PCK CRL for {}", pck_issuer);
    }

    let mut intel_collaterals = IntelCollateral::new();
    println!("set_tcbinfo_bytes: {:?}", tcb_info);
    intel_collaterals.set_tcbinfo_bytes(&tcb_info);
    println!("set_qeidentity_bytes: {:?}", qe_identity);
    intel_collaterals.set_qeidentity_bytes(&qe_identity);
    println!("set_intel_root_ca_der: {:?}", root_ca);
    intel_collaterals.set_intel_root_ca_der(&root_ca);
    println!("set_sgx_tcb_signing_der: {:?}", signing_ca);
    intel_collaterals.set_sgx_tcb_signing_der(&signing_ca);
    println!("set_sgx_intel_root_ca_crl_der: {:?}", root_ca_crl);
    intel_collaterals.set_sgx_intel_root_ca_crl_der(&root_ca_crl);
    println!("set_sgx_platform_crl_der: {:?}", pck_crl);
    intel_collaterals.set_sgx_platform_crl_der(&pck_crl);

    let intel_collaterals_bytes = intel_collaterals.to_bytes();

    // Step 3: Generate the input to upload to SP1 Proving Server
    let input = generate_input(&quote, &intel_collaterals_bytes);

    Ok(input)

}