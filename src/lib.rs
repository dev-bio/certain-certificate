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
        let data = include_bytes!("../assets/test/certificate.cer");
        assert!(Certificate::parse(data).is_some());
    }

    #[test]
    fn read_certificate_authority() {
        let data = include_bytes!("../assets/test/certificate.cer");
        let certificate = Certificate::parse(data);
        assert!(certificate.is_some());
    }

    #[test]
    fn read_certificate_issuer_name() {
        let data = include_bytes!("../assets/test/certificate.cer");
        let certificate = Certificate::parse(data);

        if let Some(certificate) = certificate {
            assert_eq!(certificate.issuer_name(), Some("GTS CA 1C3"));
        }
    }

    #[test]
    fn read_certificate_issuer_country() {
        let data = include_bytes!("../assets/test/certificate.cer");
        let certificate = Certificate::parse(data);

        if let Some(certificate) = certificate {
            assert_eq!(certificate.issuer_country(), Some("US"));
        }
    }

    #[test]
    fn read_certificate_issuer_state() {
        let data = include_bytes!("../assets/test/certificate.cer");
        let certificate = Certificate::parse(data);

        if let Some(certificate) = certificate {
            assert_eq!(certificate.issuer_state(), None);
        }
    }

    #[test]
    fn read_certificate_issuer_organization() {
        let data = include_bytes!("../assets/test/certificate.cer");
        let certificate = Certificate::parse(data);

        if let Some(certificate) = certificate {
            assert_eq!(certificate.issuer_organization(), Some("Google Trust Services LLC"));
        }
    }

    #[test]
    fn read_certificate_issuer_organizational_unit() {
        let data = include_bytes!("../assets/test/certificate.cer");
        let certificate = Certificate::parse(data);

        if let Some(certificate) = certificate {
            assert_eq!(certificate.issuer_organizational_unit(), None);
        }
    }

    #[test]
    fn read_certificate_subject_name() {
        let data = include_bytes!("../assets/test/certificate.cer");
        let certificate = Certificate::parse(data);

        if let Some(certificate) = certificate {
            assert_eq!(certificate.subject_name(), Some("www.google.com"));
        }
    }

    #[test]
    fn read_certificate_subject_alternate_names() {
        let data = include_bytes!("../assets/test/certificate.cer");
        let certificate = Certificate::parse(data);

        if let Some(certificate) = certificate {
            assert!(certificate.subject_alternate_names().is_empty());
        }
    }

    #[test]
    fn read_certificate_subject_country() {
        let data = include_bytes!("../assets/test/certificate.cer");
        let certificate = Certificate::parse(data);

        if let Some(certificate) = certificate {
            assert_eq!(certificate.subject_country(), None);
        }
    }

    #[test]
    fn read_certificate_subject_state() {
        let data = include_bytes!("../assets/test/certificate.cer");
        let certificate = Certificate::parse(data);

        if let Some(certificate) = certificate {
            assert_eq!(certificate.subject_state(), None);
        }
    }

    #[test]
    fn read_certificate_subject_organization() {
        let data = include_bytes!("../assets/test/certificate.cer");
        let certificate = Certificate::parse(data);

        if let Some(certificate) = certificate {
            assert_eq!(certificate.subject_organization(), None);
        }
    }

    #[test]
    fn read_certificate_subject_organizational_unit() {
        let data = include_bytes!("../assets/test/certificate.cer");
        let certificate = Certificate::parse(data);

        if let Some(certificate) = certificate {
            assert_eq!(certificate.subject_organizational_unit(), None);
        }
    }

    #[test]
    fn read_certificate_validity() {
        let data = include_bytes!("../assets/test/certificate.cer");
        let certificate = Certificate::parse(data);

        if let Some(certificate) = certificate {
            assert_eq!(certificate.validity().timestamp_begin() , 1675280639);
            assert_eq!(certificate.validity().timestamp_end() , 1682538238);
        }
    }

    #[test]
    fn read_certificate_serial() {
        let data = include_bytes!("../assets/test/certificate.cer");
        let certificate = Certificate::parse(data);

        if let Some(certificate) = certificate {
            assert_eq!(certificate.serial(), &[
                0xC3, 0x2C, 0x47, 0x55, 0x63, 0x03, 0x66, 0xDD,
                0x0A, 0x1C, 0x6E, 0x61, 0x0F, 0xA4, 0x65, 0x97,
            ]);
        }
    }
}
