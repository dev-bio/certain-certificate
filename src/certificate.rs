use std::{
    
    fmt::{

        Formatter as FmtFormatter,
        Result as FmtResult,
        Debug as FmtDebug,
    },

    net::{IpAddr},
};

use chrono::{
    
    NaiveDateTime,
    DateTime, 
    Utc,
};

use serde::{

    Deserialize, 
    Serialize,
};

use x509_parser::prelude::{

    X509Certificate, 
    TbsCertificate, 
    GeneralName, 
    FromDer,
};

#[derive(Clone, Copy, Debug)]
#[derive(Serialize, Deserialize)]
pub struct CertificateValidity {
    begin: DateTime<Utc>,
    end: DateTime<Utc>,
}

impl CertificateValidity {
    pub(crate) fn from_timestamps(begin: i64, end: i64) -> CertificateValidity {
        CertificateValidity { 
            begin: DateTime::from_utc(NaiveDateTime::from_timestamp_opt(begin.min(end), 0)
                .unwrap_or_default(), Utc), 
            end: DateTime::from_utc(NaiveDateTime::from_timestamp_opt(end.max(begin), 0)
                .unwrap_or_default(), Utc), 
        }
    }

    pub fn is_within_valid_time(&self) -> bool {
        let now = Utc::now();

        if self.end > now {
            if self.begin < now {
                return true
            }
        }

        false
    }

    pub fn timestamp_begin(&self) -> i64 {
        self.begin.timestamp()
    }

    pub fn time_begin(&self) -> DateTime<Utc> {
        self.begin.clone()
    }

    pub fn timestamp_end(&self) -> i64 {
        self.end.timestamp()
    }

    pub fn time_end(&self) -> DateTime<Utc> {
        self.end.clone()
    }
}

#[derive(Clone, Debug)]
#[derive(Serialize, Deserialize)]
pub enum CertificateAlternateName {
    Directory(String),
    Hostname(String),
    Address(String),
    Email(String),
    Uri(String),
}

impl<'a> CertificateAlternateName {
    pub fn to_string(&'a self) -> String{
        match self {
            CertificateAlternateName::Directory(ref string) => string.clone(),
            CertificateAlternateName::Hostname(ref string) => string.clone(),
            CertificateAlternateName::Address(ref string) => string.clone(),
            CertificateAlternateName::Email(ref string) => string.clone(),
            CertificateAlternateName::Uri(ref string) => string.clone(),
        }
    }

    pub fn as_str(&'a self) -> &'a str {
        match self {
            CertificateAlternateName::Directory(ref string) => string.as_str(),
            CertificateAlternateName::Hostname(ref string) => string.as_str(),
            CertificateAlternateName::Address(ref string) => string.as_str(),
            CertificateAlternateName::Email(ref string) => string.as_str(),
            CertificateAlternateName::Uri(ref string) => string.as_str(),
        }
    }
}

#[derive(Clone)]
#[derive(Serialize, Deserialize)]
pub struct CertificateData {
    pub(crate) authority: bool,
    pub(crate) issuer_name: Option<String>,
    pub(crate) issuer_country:Option<String>,
    pub(crate) issuer_state:Option<String>,
    pub(crate) issuer_organization:Option<String>,
    pub(crate) issuer_organizational_unit:Option<String>,
    pub(crate) subject_name: Option<String>,
    pub(crate) subject_alternate_names: Vec<CertificateAlternateName>,
    pub(crate) subject_country:Option<String>,
    pub(crate) subject_state:Option<String>,
    pub(crate) subject_organization:Option<String>,
    pub(crate) subject_organizational_unit:Option<String>,
    pub(crate) validity: CertificateValidity,
    pub(crate) serial: Vec<u8>,
    pub(crate) raw: Vec<u8>,
}

impl CertificateData {
    pub fn authority(&self) -> bool {
        self.authority
    }

    pub fn issuer_name(&self) -> Option<&str> {
        if let Some(ref issuer_name) = self.issuer_name {
            return Some(issuer_name.as_str())
        }

        None
    }

    pub fn issuer_country(&self) -> Option<&str> {
        if let Some(ref issuer_country) = self.issuer_country {
            return Some(issuer_country.as_str())
        }

        None
    }

    pub fn issuer_state(&self) -> Option<&str> {
        if let Some(ref issuer_state) = self.issuer_state {
            return Some(issuer_state.as_str())
        }

        None
    }

    pub fn issuer_organization(&self) -> Option<&str> {
        if let Some(ref issuer_organization) = self.issuer_organization {
            return Some(issuer_organization.as_str())
        }

        None
    }

    pub fn issuer_organizational_unit(&self) -> Option<&str> {
        if let Some(ref issuer_organizational_unit) = self.issuer_organizational_unit {
            return Some(issuer_organizational_unit.as_str())
        }

        None
    }

    pub fn subject_name(&self) -> Option<&str> {
        if let Some(ref subject_name) = self.subject_name {
            return Some(subject_name.as_str())
        }

        None
    }

    pub fn subject_alternate_names(&self) -> &[CertificateAlternateName] {
        self.subject_alternate_names.as_slice()
    }

    pub fn subject_country(&self) -> Option<&str> {
        if let Some(ref subject_country) = self.subject_country {
            return Some(subject_country.as_str())
        }

        None
    }

    pub fn subject_state(&self) -> Option<&str> {
        if let Some(ref subject_state) = self.subject_state {
            return Some(subject_state.as_str())
        }

        None
    }

    pub fn subject_organization(&self) -> Option<&str> {
        if let Some(ref subject_organization) = self.subject_organization {
            return Some(subject_organization.as_str())
        }

        None
    }

    pub fn subject_organizational_unit(&self) -> Option<&str> {
        if let Some(ref subject_organizational_unit) = self.subject_organizational_unit {
            return Some(subject_organizational_unit.as_str())
        }

        None
    }

    pub fn validity(&self) -> CertificateValidity {
        self.validity
    }

    pub fn serial(&self) -> &[u8] {
        self.serial.as_slice()
    }

    pub fn raw(&self) -> &[u8] {
        self.raw.as_slice()
    }
}

impl FmtDebug for CertificateData {
    fn fmt(&self, formatter: &mut FmtFormatter<'_>) -> FmtResult {
        formatter.debug_struct("Certificate")
            .field("authority", &(self.authority()))
            .field("issuer_name", &(self.issuer_name()))
            .field("issuer_country", &(self.issuer_country()))
            .field("issuer_state", &(self.issuer_state()))
            .field("issuer_organization", &(self.issuer_organization()))
            .field("issuer_organizational_unit", &(self.issuer_organizational_unit()))
            .field("subject_name", &(self.subject_name()))
            .field("subject_alternate_names", &(self.subject_alternate_names()))
            .field("subject_country", &(self.subject_country()))
            .field("subject_state", &(self.subject_state()))
            .field("subject_organization", &(self.subject_organization()))
            .field("subject_organizational_unit", &(self.subject_organizational_unit()))
            .field("validity", &(self.validity()))
            .finish()
    }
}

#[derive(Clone, Debug)]
#[derive(Serialize, Deserialize)]
pub enum Certificate {
    Signed(CertificateData),
    Pending(CertificateData),
}

impl Certificate {
    pub fn parse(data: &[u8]) -> Option<Certificate> {
        let (pending, remaining, certificate) = if let Ok((remaining, certificate)) = X509Certificate::from_der(data) { 
            (false, remaining, certificate.tbs_certificate) 
        } 
        
        else {
    
            if let Ok((remaining, tbs_certificate)) = TbsCertificate::from_der(data) { 
                (true, remaining, tbs_certificate) 
            }
            
            else {
                
                return None
            }
        };

        let authority = certificate.is_ca();

        let issuer_name = certificate.issuer().iter_common_name()
            .filter_map(|name| name.as_str().ok())
            .next().and_then(|name| Some({
                Some(name.to_owned())
            })).unwrap_or(None);

        let issuer_country = certificate.issuer().iter_country()
            .filter_map(|name| name.as_str().ok())
            .next().and_then(|name| Some({
                Some(name.to_owned())
            })).unwrap_or(None);

        let issuer_state = certificate.issuer().iter_state_or_province()
            .filter_map(|name| name.as_str().ok())
            .next().and_then(|name| Some({
                Some(name.to_owned())
            })).unwrap_or(None);
    
        let issuer_organization = certificate.issuer().iter_organization()
            .filter_map(|name| name.as_str().ok())
            .next().and_then(|name| Some({
                Some(name.to_owned())
            })).unwrap_or(None);

        let issuer_organizational_unit = certificate.issuer().iter_organizational_unit()
            .filter_map(|name| name.as_str().ok())
            .next().and_then(|name| Some({
                Some(name.to_owned())
            })).unwrap_or(None);
        
        let subject_name = certificate.subject().iter_common_name()
            .filter_map(|name| name.as_str().ok())
            .next().and_then(|name| Some({
                Some(name.to_owned())
            })).unwrap_or(None);

        let subject_alternate = if let Ok(Some(extension)) = certificate.subject_alternative_name() {
            extension.value.general_names.iter().filter_map(|name| match name {
                GeneralName::DirectoryName(name) => Some({
                    CertificateAlternateName::Directory(name.to_string())
                }),
                GeneralName::RFC822Name(name) => Some({
                    CertificateAlternateName::Email(name.to_string())
                }),
                GeneralName::IPAddress(octets) => Some({
                    CertificateAlternateName::Address(match octets {
                        octets if octets.len() == 4 => {
                            let mut array: [u8; 4] = Default::default();
                            for i in 0..4 { array[i] = octets[i] }
                            IpAddr::from(array).to_string()
                        },
                        octets if octets.len() == 16 => {
                            let mut array: [u8; 16] = Default::default();
                            for i in 0..16 { array[i] = octets[i] }
                            IpAddr::from(array).to_string()
                        },
                        _ => return None
                    })
                }),
                GeneralName::DNSName(name) => Some({
                    CertificateAlternateName::Hostname(name.to_string())
                }),
                GeneralName::URI(name) => Some({
                    CertificateAlternateName::Uri(name.to_string())
                }),
                _ => None,
            }).filter_map(|alternate| match alternate.clone() {
                CertificateAlternateName::Directory(ref item) |
                CertificateAlternateName::Hostname(ref item) |
                CertificateAlternateName::Address(ref item) |
                CertificateAlternateName::Email(ref item) |
                CertificateAlternateName::Uri(ref item) => {
                    if let Some(ref subject) = subject_name {
                        if item == subject.as_str() {
                            return None
                        }
                    }
    
                    Some(alternate)
                }
            }).collect()
        } else { Default::default() };

        let subject_country = certificate.subject().iter_country()
            .filter_map(|name| name.as_str().ok())
            .next().and_then(|name| Some({
                Some(name.to_owned())
            })).unwrap_or(None);

        let subject_state = certificate.subject().iter_state_or_province()
            .filter_map(|name| name.as_str().ok())
            .next().and_then(|name| Some({
                Some(name.to_owned())
            })).unwrap_or(None);

        let subject_organization = certificate.subject().iter_organization()
            .filter_map(|name| name.as_str().ok())
            .next().and_then(|name| Some({
                Some(name.to_owned())
            })).unwrap_or(None);

        let subject_organizational_unit = certificate.subject().iter_organizational_unit()
            .filter_map(|name| name.as_str().ok())
            .next().and_then(|name| Some({
                Some(name.to_owned())
            })).unwrap_or(None);
    
        let validity = {
    
            let begin = certificate.validity.not_before.timestamp();
            let end = certificate.validity.not_after.timestamp();
    
            CertificateValidity::from_timestamps(begin, end)
        };

        let serial = certificate.serial.to_bytes_be();
    
        let raw = data[..(data.len() - remaining.len())].to_vec();
    
        let data = CertificateData {
    
            authority,
            issuer_name,
            issuer_country,
            issuer_state,
            issuer_organization,
            issuer_organizational_unit,
            subject_name,
            subject_alternate_names: subject_alternate,
            subject_country,
            subject_state,
            subject_organization,
            subject_organizational_unit,
            validity,
            serial,
            raw,
        };
    
        if pending { Some(Certificate::Pending(data)) } 
        else { Some(Certificate::Signed(data)) }
    }

    pub fn authority(&self) -> bool {
        match self {
            Certificate::Signed(data) => data.authority(),
            Certificate::Pending(data) => data.authority(),
        }
    }

    pub fn issuer_name(&self) -> Option<&str> {
        match self {
            Certificate::Signed(data) => data.issuer_name(),
            Certificate::Pending(data) => data.issuer_name(),
        }
    }

    pub fn issuer_country(&self) -> Option<&str> {
        match self {
            Certificate::Signed(data) => data.issuer_country(),
            Certificate::Pending(data) => data.issuer_country(),
        }
    }

    pub fn issuer_state(&self) -> Option<&str> {
        match self {
            Certificate::Signed(data) => data.issuer_state(),
            Certificate::Pending(data) => data.issuer_state(),
        }
    }

    pub fn issuer_organization(&self) -> Option<&str> {
        match self {
            Certificate::Signed(data) => data.issuer_organization(),
            Certificate::Pending(data) => data.issuer_organization(),
        }
    }

    pub fn issuer_organizational_unit(&self) -> Option<&str> {
        match self {
            Certificate::Signed(data) => data.issuer_organizational_unit(),
            Certificate::Pending(data) => data.issuer_organizational_unit(),
        }
    }

    pub fn subject_name(&self) -> Option<&str> {
        match self {
            Certificate::Signed(data) => data.subject_name(),
            Certificate::Pending(data) => data.subject_name(),
        }
    }

    pub fn subject_alternate_names(&self) -> &[CertificateAlternateName] {
        match self {
            Certificate::Signed(data) => data.subject_alternate_names(),
            Certificate::Pending(data) => data.subject_alternate_names(),
        }
    }

    pub fn subject_country(&self) -> Option<&str> {
        match self {
            Certificate::Signed(data) => data.subject_country(),
            Certificate::Pending(data) => data.subject_country(),
        }
    }

    pub fn subject_state(&self) -> Option<&str> {
        match self {
            Certificate::Signed(data) => data.subject_state(),
            Certificate::Pending(data) => data.subject_state(),
        }
    }

    pub fn subject_organization(&self) -> Option<&str> {
        match self {
            Certificate::Signed(data) => data.subject_organization(),
            Certificate::Pending(data) => data.subject_organization(),
        }
    }

    pub fn subject_organizational_unit(&self) -> Option<&str> {
        match self {
            Certificate::Signed(data) => data.subject_organizational_unit(),
            Certificate::Pending(data) => data.subject_organizational_unit(),
        }
    }

    pub fn validity(&self) -> CertificateValidity {
        match self {
            Certificate::Signed(data) => data.validity(),
            Certificate::Pending(data) => data.validity(),
        }
    }

    pub fn serial(&self) -> &[u8] {
        match self {
            Certificate::Signed(data) => data.serial(),
            Certificate::Pending(data) => data.serial(),
        }
    }

    pub fn raw(&self) -> &[u8] {
        match self {
            Certificate::Signed(data) => data.raw(),
            Certificate::Pending(data) => data.raw(),
        }
    }
}