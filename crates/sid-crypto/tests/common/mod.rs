//! Keys and claims of the JWT provider tests. jsonwebtoken's provider is
//! process-wide and installed at most once, so every scenario that touches it
//! is a test file of its own: Cargo runs each file as a separate process,
//! whatever the runner.

#![allow(dead_code)] // each test file uses its own part

use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey};
use serde::{Deserialize, Serialize};

// Test key pairs, the same ones the client assertion tests use.
const RSA_PRIVATE_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDaJT4DGqR0ka3D\nY2I/epgzrantVqUN3BMVxe3/S3+/XpPzn0wWgo8gcuCWm/a8lgGqdZZdk94L+1/W\nwHNSt2Wz9jEzvXQ0iNG5SsShXLxMHj2LbsB+riZPH9oulhPYdd+aF3gYUeWwEAP0\nf7jbJurDSPfl57geBkf78fP4k2KmJTuEPTECJLJonvcLBmlBqBcbJuXG71qbssjT\nLxN1MxEDgY1sDwtJZleb+mEmKSDD0UQm4FAwqkeYmLPJgb/cAz1TsCmcrOloLro0\nPWAP5nKJkgk6ocvt03/h0p0gVieXJrpS/r5ivjLzJCUt74a6sTJwS1wtDVBOZngj\neodI1dDJAgMBAAECggEAGqW8PaGUZ4NwphqmsqGphD2RcYM5KhhhMfKR1DLfLeuy\nF8tUnnbQIEr8JZWzdh2+YhnXVoLEt/K65jcv1zG9QBahs8PvtSel89Qe8SWsgEFc\n7AKJS+g+2IFH9BMj5Tgf6nk1s8XUUJWiQAyWkpm+SYDpPFm6F1vV0QBhOLMbVLdj\neazcqU8VcqHcLAE8y+anqpXZNocrtf0gpnf6hbf1CPD0E17AN4xutPCgL1AvFrzN\nji8Ukc8Y5hGqMXau8P2ihAHvaF6rDHWPG/gcQIwOS/2WOsADD/hV2EAmWNEN6yRs\nvxakqvROVbSNtHytVmiHK9N3dWj2Z0ZftVI5SBUDIQKBgQD+YhGFPF3aDEFhCoYv\nIeevkn50Erzb78T/0knM2ZqV6/1M2bFC13KGn8YsdvJkixFgEoSfgtFyoHl3h3AR\nzCZwex65QFQZL8m6S9Fz2LG0L+SvqP9+Daa+EDCvwKb8Uag1LedbFV/7j8QgYrbq\nYXabBlyrRCRlkthmDcPQ/2fFIQKBgQDbiDVC79LFxmOgwjtIKWcASmzeVeEYrZ7u\noktDrvyVE6vzp80CjwXveMkjGEGTIxeesFDwBq3gHryg2esR8z187PSSaTkzwyEp\nQQEXO3wzyk06/NOv/sngZgxglPMwjrUvaq+ay8vFI+EZTVdnF10NfMlmcS432c8O\nt4nBohDuqQKBgGUq+2zRpUGivh2p4dO82DerOz9OdG3D3cUgDNm7cQ9O215E9Ypv\nxMxlnprwc1YpOK/MrZICpOnBiI1Q//EUD/WMAZwLSWb66m9818AK3iGbKofx3ipz\no2zTY4mCROb0UsFTkD9ZMOMLOiTnHXf5awIcdZ5na1I6JHXx436rFMoBAoGAIVVS\nOQKvL0aLVBqJ49AdiqbCVxQVJKkgK73KzdEhGwWso0eEUnIjBZSCfeit9EhsyrSc\n5YUuG4yvOYE9NzGG0ZQtIpoFjH2BaIEtSDjJCBgcl+tRvTRjtMXp9TRIpMPWcQey\n+D8fhqSHBk9/CPE8ONMMxZhD20kgLmzh5tvT1FkCgYAilY/8UMJEEFrPHFSSl4o+\nqvwJFz6K257Pyx0hKS+hXq1WNdgx9tXLm40u53tlvRW1rLKXUv8Fxt0AA/iatZwB\nXsowtKPYS4gXlBrazjwIinjF+Rpj5mpQjhd8Ta3wWZcsW7UkaMuHb5pbk4Y9WrGx\n32y+KDbk0EXdAqJn2zUwBw==\n-----END PRIVATE KEY-----";
const RSA_PUBLIC_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2iU+AxqkdJGtw2NiP3qY\nM62p7ValDdwTFcXt/0t/v16T859MFoKPIHLglpv2vJYBqnWWXZPeC/tf1sBzUrdl\ns/YxM710NIjRuUrEoVy8TB49i27Afq4mTx/aLpYT2HXfmhd4GFHlsBAD9H+42ybq\nw0j35ee4HgZH+/Hz+JNipiU7hD0xAiSyaJ73CwZpQagXGyblxu9am7LI0y8TdTMR\nA4GNbA8LSWZXm/phJikgw9FEJuBQMKpHmJizyYG/3AM9U7ApnKzpaC66ND1gD+Zy\niZIJOqHL7dN/4dKdIFYnlya6Uv6+Yr4y8yQlLe+GurEycEtcLQ1QTmZ4I3qHSNXQ\nyQIDAQAB\n-----END PUBLIC KEY-----";
const EC_PRIVATE_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg5N2eJG8rPodJbdAX\nfChoMXCZkpJqlz0PNNWZoxQNRzOhRANCAARa90QK2ST6bdJvXRUvsVGsnoqX4AxY\nsblCcfcVl0daQBhY/6Hn4Hgk55T1rYmyPz38tvEadpq9KRpkKzsszUl9\n-----END PRIVATE KEY-----";
const EC_PUBLIC_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEWvdECtkk+m3Sb10VL7FRrJ6Kl+AM\nWLG5QnH3FZdHWkAYWP+h5+B4JOeU9a2Jsj89/LbxGnaavSkaZCs7LM1JfQ==\n-----END PUBLIC KEY-----";
const ED_PRIVATE_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIGnMIVUgwI0tTO1AANoNzICml1zLy8M4WqrJlomrTGlU\n-----END PRIVATE KEY-----";
const ED_PUBLIC_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAqK9dvWXRiLy73AXFvVRAMzmlQwKF6q/R/UJmjngfLLs=\n-----END PUBLIC KEY-----";

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct Claims {
    pub sub: String,
    pub exp: u64,
}

pub fn claims() -> Claims {
    Claims {
        sub: "0192f3a4-7c1e-7b2a-9d4e-3f5a6b7c8d9e".into(),
        exp: 4_102_444_800,
    }
}

/// Each admitted algorithm's signing and verification keys.
pub fn keys(alg: Algorithm) -> (EncodingKey, DecodingKey) {
    match alg {
        Algorithm::RS256 | Algorithm::PS256 => (
            EncodingKey::from_rsa_pem(RSA_PRIVATE_PEM.as_bytes()).unwrap(),
            DecodingKey::from_rsa_pem(RSA_PUBLIC_PEM.as_bytes()).unwrap(),
        ),
        Algorithm::ES256 => (
            EncodingKey::from_ec_pem(EC_PRIVATE_PEM.as_bytes()).unwrap(),
            DecodingKey::from_ec_pem(EC_PUBLIC_PEM.as_bytes()).unwrap(),
        ),
        Algorithm::EdDSA => (
            EncodingKey::from_ed_pem(ED_PRIVATE_PEM.as_bytes()).unwrap(),
            DecodingKey::from_ed_pem(ED_PUBLIC_PEM.as_bytes()).unwrap(),
        ),
        other => panic!("no test key for {other:?}"),
    }
}
