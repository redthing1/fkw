use crate::{
    ApplicationId, CredentialStorage, Error, KdfCost, KeyOptions, Method, MethodId, Result,
    StoreAccess, Verification, crypto, methods::validate_label,
};
use minicbor::{Decoder, Encoder, data::Type};
use std::convert::Infallible;

pub(crate) const MAX_METHODS: usize = 32;
pub const MAX_ENVELOPE_BYTES: usize = 65_536;
type Enc = Encoder<Vec<u8>>;
type EncodeResult = std::result::Result<(), minicbor::encode::Error<Infallible>>;

/// Opaque public metadata. Decoding validates structure, not authenticity.
/// Trust displayed metadata only after successfully unlocking this envelope.
#[derive(Clone, Debug)]
pub struct Envelope {
    pub(crate) application: ApplicationId,
    pub(crate) id: [u8; 32],
    pub(crate) records: Vec<Record>,
    pub(crate) mac: [u8; 32],
}
#[derive(Clone, Debug)]
pub(crate) struct Credential {
    pub id: Vec<u8>,
    pub public_key: [u8; 64],
}
#[derive(Clone, Debug)]
pub(crate) struct Kdf {
    pub cost: KdfCost,
    pub salt: [u8; 16],
}
#[derive(Clone, Debug)]
pub(crate) struct Record {
    pub id: MethodId,
    pub label: String,
    pub method: Method,
    pub kdf: Option<Kdf>,
    pub credential: Option<Credential>,
    pub nonce: [u8; 12],
    pub wrapped: Vec<u8>,
}
/// Read-only method metadata. Authentication depends on the containing envelope.
#[derive(Clone, Copy, Debug)]
pub struct MethodInfo<'a> {
    pub id: MethodId,
    pub label: &'a str,
    pub method: Method,
    pub kdf_cost: Option<KdfCost>,
}
impl Envelope {
    /// Maximum encoded size, for bounded reads before decoding.
    pub const MAX_BYTES: usize = MAX_ENVELOPE_BYTES;

    #[must_use]
    pub const fn application_id(&self) -> &ApplicationId {
        &self.application
    }
    #[must_use]
    pub const fn id(&self) -> &[u8; 32] {
        &self.id
    }
    pub fn methods(&self) -> impl ExactSizeIterator<Item = MethodInfo<'_>> {
        self.records.iter().map(|r| MethodInfo {
            id: r.id,
            label: &r.label,
            method: r.method,
            kdf_cost: r.kdf.as_ref().map(|k| k.cost),
        })
    }
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut e = Encoder::new(b"FKWE".to_vec());
        self.encode(&mut e, true)
            .expect("Vec encoding is infallible");
        e.into_writer()
    }
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_ENVELOPE_BYTES || !bytes.starts_with(b"FKWE") {
            return Err(Error::InvalidEnvelope);
        }
        let mut d = Decoder::new(&bytes[4..]);
        let parsed = decode(&mut d).map_err(|_| Error::InvalidEnvelope)?;
        if d.position() != bytes.len() - 4 || parsed.to_bytes() != bytes {
            return Err(Error::InvalidEnvelope);
        }
        Ok(parsed)
    }
    pub(crate) fn body(&self) -> Vec<u8> {
        let mut e = Encoder::new(Vec::new());
        self.encode(&mut e, false)
            .expect("Vec encoding is infallible");
        e.into_writer()
    }
    fn encode(&self, e: &mut Enc, include_mac: bool) -> EncodeResult {
        e.array(if include_mac { 5 } else { 4 })?
            .u8(2)?
            .str(self.application.as_str())?
            .bytes(&self.id)?
            .array(self.records.len() as u64)?;
        for record in &self.records {
            record.encode(e, true)?;
        }
        if include_mac {
            e.bytes(&self.mac)?;
        }
        Ok(())
    }
    pub(crate) fn record(&self, id: MethodId) -> Result<&Record> {
        self.records
            .iter()
            .find(|r| r.id == id)
            .ok_or(Error::MethodNotFound)
    }
    pub(crate) fn sign(&mut self, root: &[u8; 32]) {
        self.mac = crypto::mac(&self.mac_key(root), &self.body());
    }
    pub(crate) fn verify(&self, root: &[u8; 32]) -> Result<()> {
        crypto::verify_mac(&self.mac_key(root), &self.body(), &self.mac)
    }
    fn mac_key(&self, root: &[u8; 32]) -> zeroize::Zeroizing<[u8; 32]> {
        crypto::derive(
            root,
            &self.id,
            &[b"fkw/v2/envelope", self.application.as_str().as_bytes()],
        )
    }
}
impl Record {
    pub(crate) fn context(&self, app: &ApplicationId, envelope_id: &[u8; 32]) -> [u8; 32] {
        let mut e = Encoder::new(Vec::new());
        self.encode(&mut e, false)
            .expect("Vec encoding is infallible");
        crypto::hash(&[
            b"fkw/v2/method",
            app.as_str().as_bytes(),
            envelope_id,
            &e.into_writer(),
        ])
    }
    fn encode(&self, e: &mut Enc, wrapped: bool) -> EncodeResult {
        e.array(if wrapped { 7 } else { 6 })?
            .bytes(self.id.as_bytes())?
            .str(&self.label)?;
        encode_method(e, self.method)?;
        if let Some(k) = &self.kdf {
            e.array(4)?
                .u32(k.cost.memory)?
                .u32(k.cost.passes)?
                .u32(k.cost.lanes)?
                .bytes(&k.salt)?;
        } else {
            e.null()?;
        }
        if let Some(c) = &self.credential {
            e.array(2)?.bytes(&c.id)?.bytes(&c.public_key)?;
        } else {
            e.null()?;
        }
        e.bytes(&self.nonce)?;
        if wrapped {
            e.bytes(&self.wrapped)?;
        }
        Ok(())
    }
}
fn encode_method(e: &mut Enc, method: Method) -> EncodeResult {
    let (kind, length) = match method {
        Method::Passphrase => (0, 1),
        Method::SecurityKey(_) => (1, 3),
        Method::Keystore(_) => (2, 2),
        Method::KeyAndPassphrase(_) => (3, 3),
        Method::KeyAndKeystore(_, _) => (4, 4),
        Method::RecoverySecret => (5, 1),
    };
    e.array(length)?.u8(kind)?;
    if let Some(k) = method.key_options() {
        e.u8(match k.verification {
            Verification::Presence => 0,
            Verification::UserVerified => 1,
        })?
        .u8(match k.storage {
            CredentialStorage::NonDiscoverable => 0,
            CredentialStorage::Managed => 1,
        })?;
    }
    if let Some(a) = method.store_access() {
        e.u8(match a {
            StoreAccess::Standard => 0,
            StoreAccess::UserAuthentication => 1,
            StoreAccess::MacosLogin => 2,
        })?;
    }
    Ok(())
}
type DecodeResult<T> = std::result::Result<T, minicbor::decode::Error>;
fn invalid() -> minicbor::decode::Error {
    minicbor::decode::Error::message("invalid envelope")
}
fn array(d: &mut Decoder<'_>, len: u64) -> DecodeResult<()> {
    if d.array()? != Some(len) {
        return Err(invalid());
    }
    Ok(())
}
fn bytes<const N: usize>(d: &mut Decoder<'_>) -> DecodeResult<[u8; N]> {
    d.bytes()?.try_into().map_err(|_| invalid())
}
fn decode(d: &mut Decoder<'_>) -> DecodeResult<Envelope> {
    array(d, 5)?;
    if d.u8()? != 2 {
        return Err(invalid());
    }
    let application = ApplicationId::new(d.str()?).map_err(|_| invalid())?;
    let id = bytes(d)?;
    let len = d.array()?.ok_or_else(invalid)?;
    if !(1..=MAX_METHODS as u64).contains(&len) {
        return Err(invalid());
    }
    let mut records = Vec::new();
    for _ in 0..len {
        let record = decode_record(d)?;
        if records.iter().any(|r: &Record| r.id == record.id) {
            return Err(invalid());
        }
        records.push(record);
    }
    Ok(Envelope {
        application,
        id,
        records,
        mac: bytes(d)?,
    })
}
fn decode_record(d: &mut Decoder<'_>) -> DecodeResult<Record> {
    array(d, 7)?;
    let id = MethodId::from_bytes(bytes(d)?);
    let label = d.str()?;
    validate_label(label).map_err(|_| invalid())?;
    let label = label.to_owned();
    let method = decode_method(d)?;
    let kdf = if d.datatype()? == Type::Null {
        d.null()?;
        None
    } else {
        array(d, 4)?;
        Some(Kdf {
            cost: KdfCost::new(d.u32()?, d.u32()?, d.u32()?).map_err(|_| invalid())?,
            salt: bytes(d)?,
        })
    };
    let credential = if d.datatype()? == Type::Null {
        d.null()?;
        None
    } else {
        array(d, 2)?;
        let id = d.bytes()?;
        if id.is_empty() || id.len() > 1024 {
            return Err(invalid());
        }
        let public_key = bytes(d)?;
        let mut sec1 = [4u8; 65];
        sec1[1..].copy_from_slice(&public_key);
        p256::PublicKey::from_sec1_bytes(&sec1).map_err(|_| invalid())?;
        Some(Credential {
            id: id.to_vec(),
            public_key,
        })
    };
    if method.needs_passphrase() != kdf.is_some()
        || method.key_options().is_some() != credential.is_some()
    {
        return Err(invalid());
    }
    let nonce = bytes(d)?;
    let wrapped = d.bytes()?;
    let expected = if matches!(method, Method::KeyAndPassphrase(_)) {
        64
    } else {
        48
    };
    if wrapped.len() != expected {
        return Err(invalid());
    }
    Ok(Record {
        id,
        label,
        method,
        kdf,
        credential,
        nonce,
        wrapped: wrapped.to_vec(),
    })
}
fn decode_method(d: &mut Decoder<'_>) -> DecodeResult<Method> {
    let len = d.array()?.ok_or_else(invalid)?;
    let kind = d.u8()?;
    Ok(match (kind, len) {
        (0, 1) => Method::Passphrase,
        (1, 3) => Method::SecurityKey(decode_key(d)?),
        (2, 2) => Method::Keystore(decode_access(d)?),
        (3, 3) => Method::KeyAndPassphrase(decode_key(d)?),
        (4, 4) => Method::KeyAndKeystore(decode_key(d)?, decode_access(d)?),
        (5, 1) => Method::RecoverySecret,
        _ => return Err(invalid()),
    })
}
fn decode_key(d: &mut Decoder<'_>) -> DecodeResult<KeyOptions> {
    let verification = match d.u8()? {
        0 => Verification::Presence,
        1 => Verification::UserVerified,
        _ => return Err(invalid()),
    };
    let storage = match d.u8()? {
        0 => CredentialStorage::NonDiscoverable,
        1 => CredentialStorage::Managed,
        _ => return Err(invalid()),
    };
    Ok(KeyOptions {
        verification,
        storage,
    })
}
fn decode_access(d: &mut Decoder<'_>) -> DecodeResult<StoreAccess> {
    match d.u8()? {
        0 => Ok(StoreAccess::Standard),
        1 => Ok(StoreAccess::UserAuthentication),
        2 => Ok(StoreAccess::MacosLogin),
        _ => Err(invalid()),
    }
}
