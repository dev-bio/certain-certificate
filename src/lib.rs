pub fn add(left: usize, right: usize) -> usize {
    left + right
}

mod certificate;

pub use certificate::{
    CertificateValidity,
    CertificateData,
    Certificate,
};

#[cfg(test)]
mod tests {

    use super::{Certificate};

    #[test]
    fn parse_certificate() {
        assert!(Certificate::parse(include_bytes!("./test_data/certificate.cer")).is_some());
    }

    #[test]
    fn read_certificate() {
        let certificate = Certificate::parse(include_bytes!("./test_data/certificate.cer"));
        assert!(certificate.is_some());

        if let Some(certificate) = certificate {
            assert_eq!(certificate.authority(), false);

            assert_eq!(certificate.issuer_name(), Some("GTS CA 1C3"));
            assert_eq!(certificate.issuer_country(), Some("US"));
            assert_eq!(certificate.issuer_state(), None);
            assert_eq!(certificate.issuer_organization(), Some("Google Trust Services LLC"));
            assert_eq!(certificate.issuer_organizational_unit(), None);

            assert_eq!(certificate.subject_name(), Some("www.google.com"));
            assert!(certificate.subject_alternate_names().is_empty());
            assert_eq!(certificate.subject_country(), None);
            assert_eq!(certificate.subject_state(), None);
            assert_eq!(certificate.subject_organization(), None);
            assert_eq!(certificate.subject_organizational_unit(), None);

            assert_eq!(certificate.validity().timestamp_begin() , 1675280639);
            assert_eq!(certificate.validity().timestamp_end() , 1682538238);

            assert_eq!(certificate.serial(), &[
                0xC3, 0x2C, 0x47, 0x55, 0x63, 0x03, 0x66, 0xDD,
                0x0A, 0x1C, 0x6E, 0x61, 0x0F, 0xA4, 0x65, 0x97,
            ]);

            assert_eq!(certificate.raw(), include_bytes!("./test_data/certificate.cer"));
        }
    }
}
