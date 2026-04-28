use fcp_core::util::to_kebab_case;

#[test]
fn kebab_case_converter_pins_boundary_inputs() {
    let cases = [
        ("", ""),
        ("A", "a"),
        ("audit", "audit"),
        ("AuditReceiptEnvelope", "audit-receipt-envelope"),
        ("FCP3Receipt42Envelope", "fcp3-receipt42-envelope"),
        ("  Audit Receipt  ", "audit-receipt"),
        ("audit--receipt", "audit-receipt"),
    ];

    for (input, expected) in cases {
        assert_eq!(to_kebab_case(input), expected, "input: {input:?}");
    }
}
