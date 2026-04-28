use fcp_core::{PortNumberValidationError, validate_port_number};

#[test]
fn port_number_validator_accepts_boundary_values() {
    for (raw, expected) in [
        (0_i64, 0_u16),
        (1, 1),
        (1023, 1023),
        (1024, 1024),
        (65_534, 65_534),
        (65_535, 65_535),
    ] {
        assert_eq!(validate_port_number(raw), Ok(expected));
    }
}

#[test]
fn port_number_validator_rejects_out_of_range_values() {
    for port in [65_536_i64, -1] {
        assert_eq!(
            validate_port_number(port),
            Err(PortNumberValidationError::OutOfRange {
                value: port,
                min: 0,
                max: u16::MAX
            })
        );
    }
}
