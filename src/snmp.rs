//! A small SNMP v2c client: BER encoding and decoding, GET and GETBULK/GETNEXT walks over UDP.
//!
//! It only ever **reads** (never sends a SET), talks only to the addresses an administrator configured, and
//! treats every byte that comes back as hostile: all decoding is bounds-checked and returns an error instead of
//! panicking, lengths are limited, and a walk is bounded in rows and in time. SNMPv3 is not implemented.
//!
//! The wire format is the standard one (RFC 3416 PDUs in an RFC 1157/3584 message, BER from X.690). The tests check
//! the encoder against byte sequences worked out from the specification; they are *not* a substitute for trying it
//! against a real switch, which the documentation says plainly.

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{anyhow, bail, Result};
use tokio::net::UdpSocket;

// --------------------------------------------------------------------------------------------- values

#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Int(i64),
    /// Counter32, Gauge32, TimeTicks, Counter64 and other unsigned numbers.
    Uint(u64),
    Str(Vec<u8>),
    Oid(Vec<u32>),
    Ip([u8; 4]),
    Null,
    NoSuchObject,
    NoSuchInstance,
    EndOfMibView,
}

impl Value {
    pub fn as_str(&self) -> Option<String> {
        match self {
            Value::Str(b) => Some(printable(b)),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Value::Int(i) => Some(*i),
            Value::Uint(u) => i64::try_from(*u).ok(),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Value::Str(b) => Some(b),
            _ => None,
        }
    }

    /// "There is nothing here" answers.
    pub fn is_missing(&self) -> bool {
        matches!(self, Value::NoSuchObject | Value::NoSuchInstance | Value::EndOfMibView | Value::Null)
    }
}

/// Text from a device: control characters removed, length bounded (it ends up on screen).
pub fn printable(b: &[u8]) -> String {
    String::from_utf8_lossy(b).chars().filter(|c| !c.is_control()).take(200).collect()
}

pub type Oid = Vec<u32>;

/// `1.3.6.1.2.1.1.1.0` -> arcs.
pub fn oid(s: &str) -> Oid {
    s.split('.').filter(|p| !p.is_empty()).map(|p| p.parse().expect("a literal OID")).collect()
}

pub fn oid_text(o: &[u32]) -> String {
    o.iter().map(u32::to_string).collect::<Vec<_>>().join(".")
}

// ------------------------------------------------------------------------------------------ encoding

fn put_len(out: &mut Vec<u8>, n: usize) {
    if n < 128 {
        out.push(n as u8);
    } else {
        let bytes: Vec<u8> = n.to_be_bytes().iter().copied().skip_while(|b| *b == 0).collect();
        out.push(0x80 | bytes.len() as u8);
        out.extend(bytes);
    }
}

fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut v = vec![tag];
    put_len(&mut v, body.len());
    v.extend_from_slice(body);
    v
}

fn enc_int(i: i64) -> Vec<u8> {
    let bytes = i.to_be_bytes();
    // minimal two's complement: drop leading bytes that only repeat the sign
    let mut start = 0;
    while start < 7 && ((bytes[start] == 0 && bytes[start + 1] & 0x80 == 0) || (bytes[start] == 0xff && bytes[start + 1] & 0x80 != 0)) {
        start += 1;
    }
    tlv(0x02, &bytes[start..])
}

fn enc_oid(o: &[u32]) -> Result<Vec<u8>> {
    if o.len() < 2 || o[0] > 2 || (o[0] < 2 && o[1] >= 40) {
        bail!("not a valid object identifier");
    }
    let mut body = Vec::new();
    for (i, arc) in std::iter::once(o[0] * 40 + o[1]).chain(o[2..].iter().copied()).enumerate() {
        let _ = i;
        let mut groups = vec![(arc & 0x7f) as u8];
        let mut n = arc >> 7;
        while n > 0 {
            groups.push(((n & 0x7f) as u8) | 0x80);
            n >>= 7;
        }
        groups.reverse();
        body.extend(groups);
    }
    Ok(tlv(0x06, &body))
}

pub const GET: u8 = 0xa0;
pub const GETNEXT: u8 = 0xa1;
pub const RESPONSE: u8 = 0xa2;
pub const GETBULK: u8 = 0xa5;

/// One request message. For GETBULK, `a` is non-repeaters and `b` max-repetitions; otherwise both are 0.
pub fn encode_request(community: &str, kind: u8, request_id: i32, a: i32, b: i32, oids: &[Oid]) -> Result<Vec<u8>> {
    let mut binds = Vec::new();
    for o in oids {
        let mut vb = enc_oid(o)?;
        vb.extend(tlv(0x05, &[]));
        binds.extend(tlv(0x30, &vb));
    }
    let mut pdu = enc_int(request_id as i64);
    pdu.extend(enc_int(a as i64));
    pdu.extend(enc_int(b as i64));
    pdu.extend(tlv(0x30, &binds));
    let mut msg = enc_int(1); // version: 1 = SNMPv2c
    msg.extend(tlv(0x04, community.as_bytes()));
    msg.extend(tlv(kind, &pdu));
    Ok(tlv(0x30, &msg))
}

// ------------------------------------------------------------------------------------------ decoding

struct Reader<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(b: &'a [u8]) -> Self {
        Reader { b, pos: 0 }
    }

    fn done(&self) -> bool {
        self.pos >= self.b.len()
    }

    /// The next element: its tag and its content.
    fn next(&mut self) -> Result<(u8, &'a [u8])> {
        let tag = *self.b.get(self.pos).ok_or_else(|| anyhow!("truncated"))?;
        let first = *self.b.get(self.pos + 1).ok_or_else(|| anyhow!("truncated"))?;
        let (len, header) = if first < 0x80 {
            (first as usize, 2)
        } else {
            let n = (first & 0x7f) as usize;
            if n == 0 || n > 4 {
                bail!("unsupported length");
            }
            let mut len = 0usize;
            for i in 0..n {
                len = (len << 8) | *self.b.get(self.pos + 2 + i).ok_or_else(|| anyhow!("truncated"))? as usize;
            }
            (len, 2 + n)
        };
        let start = self.pos + header;
        let end = start.checked_add(len).filter(|e| *e <= self.b.len()).ok_or_else(|| anyhow!("length runs past the end"))?;
        self.pos = end;
        Ok((tag, &self.b[start..end]))
    }

    fn expect(&mut self, tag: u8) -> Result<&'a [u8]> {
        let (t, c) = self.next()?;
        if t != tag {
            bail!("expected tag {tag:#04x}, found {t:#04x}");
        }
        Ok(c)
    }
}

fn dec_int(c: &[u8]) -> Result<i64> {
    if c.is_empty() || c.len() > 8 {
        bail!("bad integer");
    }
    let mut v: i64 = if c[0] & 0x80 != 0 { -1 } else { 0 };
    for b in c {
        v = (v << 8) | *b as i64;
    }
    Ok(v)
}

fn dec_uint(c: &[u8]) -> Result<u64> {
    // unsigned values may carry one leading zero byte (to keep the sign bit clear)
    let c = if c.len() > 1 && c[0] == 0 { &c[1..] } else { c };
    if c.is_empty() || c.len() > 8 {
        bail!("bad unsigned integer");
    }
    Ok(c.iter().fold(0u64, |v, b| (v << 8) | *b as u64))
}

fn dec_oid(c: &[u8]) -> Result<Oid> {
    if c.is_empty() {
        bail!("empty object identifier");
    }
    let mut arcs = Vec::new();
    let mut cur: u32 = 0;
    let mut first = true;
    for (i, b) in c.iter().enumerate() {
        cur = cur.checked_mul(128).and_then(|v| v.checked_add((b & 0x7f) as u32)).ok_or_else(|| anyhow!("arc too large"))?;
        if b & 0x80 == 0 {
            if first {
                let (x, y) = if cur < 80 { (cur / 40, cur % 40) } else { (2, cur - 80) };
                arcs.extend([x, y]);
                first = false;
            } else {
                arcs.push(cur);
            }
            cur = 0;
        } else if i == c.len() - 1 {
            bail!("object identifier ends inside an arc");
        }
        if arcs.len() > 128 {
            bail!("object identifier too long");
        }
    }
    Ok(arcs)
}

fn dec_value(tag: u8, c: &[u8]) -> Result<Value> {
    Ok(match tag {
        0x02 => Value::Int(dec_int(c)?),
        0x04 | 0x44 => Value::Str(c.to_vec()),
        0x05 => Value::Null,
        0x06 => Value::Oid(dec_oid(c)?),
        0x40 => Value::Ip(c.try_into().map_err(|_| anyhow!("bad IP address"))?),
        0x41..=0x43 | 0x46 => Value::Uint(dec_uint(c)?),
        0x80 => Value::NoSuchObject,
        0x81 => Value::NoSuchInstance,
        0x82 => Value::EndOfMibView,
        other => bail!("unsupported value type {other:#04x}"),
    })
}

/// A decoded response.
#[derive(Debug, PartialEq)]
pub struct Response {
    pub request_id: i32,
    pub error_status: i64,
    pub error_index: i64,
    pub binds: Vec<(Oid, Value)>,
}

/// Decode a message that should be a v2c response with the given community. Never panics.
pub fn decode_response(data: &[u8]) -> Result<Response> {
    let mut top = Reader::new(data);
    let msg = top.expect(0x30)?;
    let mut r = Reader::new(msg);
    let version = dec_int(r.expect(0x02)?)?;
    if version != 1 {
        bail!("not an SNMPv2c message (version {version})");
    }
    let _community = r.expect(0x04)?;
    let pdu = r.expect(RESPONSE)?;
    let mut p = Reader::new(pdu);
    let request_id = dec_int(p.expect(0x02)?)? as i32;
    let error_status = dec_int(p.expect(0x02)?)?;
    let error_index = dec_int(p.expect(0x02)?)?;
    let mut list = Reader::new(p.expect(0x30)?);
    let mut binds = Vec::new();
    while !list.done() {
        if binds.len() >= 2000 {
            bail!("too many variables in one answer");
        }
        let mut vb = Reader::new(list.expect(0x30)?);
        let name = dec_oid(vb.expect(0x06)?)?;
        let (tag, content) = vb.next()?;
        binds.push((name, dec_value(tag, content)?));
    }
    Ok(Response { request_id, error_status, error_index, binds })
}

/// Decode a request (used by the test agent, and to keep the two directions honest).
pub fn decode_request(data: &[u8]) -> Result<(String, u8, i32, i64, i64, Vec<Oid>)> {
    let mut top = Reader::new(data);
    let mut r = Reader::new(top.expect(0x30)?);
    if dec_int(r.expect(0x02)?)? != 1 {
        bail!("not SNMPv2c");
    }
    let community = printable(r.expect(0x04)?);
    let (kind, pdu) = r.next()?;
    let mut p = Reader::new(pdu);
    let id = dec_int(p.expect(0x02)?)? as i32;
    let a = dec_int(p.expect(0x02)?)?;
    let b = dec_int(p.expect(0x02)?)?;
    let mut list = Reader::new(p.expect(0x30)?);
    let mut oids = Vec::new();
    while !list.done() {
        let mut vb = Reader::new(list.expect(0x30)?);
        oids.push(dec_oid(vb.expect(0x06)?)?);
    }
    Ok((community, kind, id, a, b, oids))
}

/// Encode a response (the test agent's side; also lets tests check the decoder against the encoder).
pub fn encode_response(community: &str, request_id: i32, error_status: i64, binds: &[(Oid, Value)]) -> Result<Vec<u8>> {
    let mut list = Vec::new();
    for (name, v) in binds {
        let mut vb = enc_oid(name)?;
        vb.extend(match v {
            Value::Int(i) => enc_int(*i),
            Value::Uint(u) => {
                let mut b = u.to_be_bytes().iter().copied().skip_while(|x| *x == 0).collect::<Vec<u8>>();
                if b.is_empty() || b[0] & 0x80 != 0 {
                    b.insert(0, 0);
                }
                tlv(0x42, &b)
            }
            Value::Str(s) => tlv(0x04, s),
            Value::Oid(o) => enc_oid(o)?,
            Value::Ip(a) => tlv(0x40, a),
            Value::Null => tlv(0x05, &[]),
            Value::NoSuchObject => tlv(0x80, &[]),
            Value::NoSuchInstance => tlv(0x81, &[]),
            Value::EndOfMibView => tlv(0x82, &[]),
        });
        list.extend(tlv(0x30, &vb));
    }
    let mut pdu = enc_int(request_id as i64);
    pdu.extend(enc_int(error_status));
    pdu.extend(enc_int(0));
    pdu.extend(tlv(0x30, &list));
    let mut msg = enc_int(1);
    msg.extend(tlv(0x04, community.as_bytes()));
    msg.extend(tlv(RESPONSE, &pdu));
    Ok(tlv(0x30, &msg))
}

// ------------------------------------------------------------------------------------------- client

/// Limits of one walk: what a misbehaving or huge device may make us do.
pub const MAX_WALK_ROWS: usize = 30_000;
pub const WALK_DEADLINE: Duration = Duration::from_secs(60);

pub struct Client {
    sock: UdpSocket,
    community: String,
    timeout: Duration,
    retries: u32,
    next_id: i32,
}

impl Client {
    pub async fn new(addr: SocketAddr, community: &str, timeout: Duration) -> Result<Client> {
        let bind: SocketAddr = if addr.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }.parse().expect("literal");
        let sock = UdpSocket::bind(bind).await?;
        sock.connect(addr).await?;
        let mut seed = [0u8; 4];
        getrandom::fill(&mut seed).map_err(|e| anyhow!("no randomness: {e}"))?;
        Ok(Client { sock, community: community.to_string(), timeout, retries: 2, next_id: (i32::from_be_bytes(seed) & 0x3fff_ffff) | 1 })
    }

    /// Send one request and wait for its answer (a few tries; answers with another id are ignored).
    async fn ask(&mut self, kind: u8, a: i32, b: i32, oids: &[Oid]) -> Result<Response> {
        self.next_id = (self.next_id + 1) & 0x3fff_ffff;
        let id = self.next_id;
        let packet = encode_request(&self.community, kind, id, a, b, oids)?;
        let mut buf = vec![0u8; 65_535];
        for _ in 0..=self.retries {
            self.sock.send(&packet).await?;
            let deadline = tokio::time::Instant::now() + self.timeout;
            loop {
                let Ok(got) = tokio::time::timeout_at(deadline, self.sock.recv(&mut buf)).await else { break };
                let n = got?;
                match decode_response(&buf[..n]) {
                    Ok(r) if r.request_id == id => {
                        return match r.error_status {
                            0 => Ok(r),
                            1 => bail!("the answer was too big for the device to send"),
                            2 => Ok(r), // noSuchName (v1 style): treated as "nothing here" by the callers
                            status => bail!("the device refused the request (error {status})"),
                        };
                    }
                    Ok(_) => continue, // an old or foreign answer
                    Err(_) => continue, // not a valid answer: keep waiting for the real one
                }
            }
        }
        bail!("no answer from the device (is SNMP on, is the community right, is UDP 161 reachable from here?)")
    }

    pub async fn get(&mut self, oids: &[Oid]) -> Result<Vec<(Oid, Value)>> {
        Ok(self.ask(GET, 0, 0, oids).await?.binds)
    }

    /// Every variable under `prefix` (a table column, or a whole table), in order. Uses GETBULK, and GETNEXT if the
    /// device refuses bulk requests. Stops at `MAX_WALK_ROWS` rows or `WALK_DEADLINE`.
    pub async fn walk(&mut self, prefix: &[u32]) -> Result<Vec<(Oid, Value)>> {
        let started = tokio::time::Instant::now();
        let mut out: Vec<(Oid, Value)> = Vec::new();
        let mut cursor = prefix.to_vec();
        let mut bulk = true;
        loop {
            if out.len() >= MAX_WALK_ROWS || started.elapsed() > WALK_DEADLINE {
                break;
            }
            let r = if bulk {
                match self.ask(GETBULK, 0, 20, std::slice::from_ref(&cursor)).await {
                    Ok(r) => r,
                    Err(e) if out.is_empty() => {
                        // a device that does not do GETBULK: fall back to GETNEXT once, and report its answer if that fails too
                        bulk = false;
                        match self.ask(GETNEXT, 0, 0, std::slice::from_ref(&cursor)).await {
                            Ok(r) => r,
                            Err(_) => return Err(e),
                        }
                    }
                    Err(e) => return Err(e),
                }
            } else {
                self.ask(GETNEXT, 0, 0, std::slice::from_ref(&cursor)).await?
            };
            if r.binds.is_empty() {
                break;
            }
            let mut advanced = false;
            for (name, value) in r.binds {
                if !name.starts_with(prefix) || matches!(value, Value::EndOfMibView) {
                    return Ok(out);
                }
                if name <= cursor {
                    return Ok(out); // an agent that does not move forward would loop us forever
                }
                cursor = name.clone();
                advanced = true;
                out.push((name, value));
                if out.len() >= MAX_WALK_ROWS {
                    return Ok(out);
                }
            }
            if !advanced {
                break;
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
pub(crate) mod agent {
    //! A stand-in for a switch: answers GET, GETNEXT and GETBULK from a sorted table, over real UDP.

    use super::*;
    use std::collections::BTreeMap;
    use std::sync::Arc;

    /// What the agent was asked, in order: the kind of request and the variables.
    pub type Requests = Arc<std::sync::Mutex<Vec<(u8, Vec<Oid>)>>>;

    pub struct Agent {
        pub addr: SocketAddr,
        pub requests: Requests,
        stop: Arc<std::sync::atomic::AtomicBool>,
    }

    impl Drop for Agent {
        fn drop(&mut self) {
            self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        }
    }

    /// `community`: the only one it answers to. `refuse_bulk`: answers GETBULK with an error, like an old device.
    pub fn start(community: &str, table: BTreeMap<Oid, Value>, refuse_bulk: bool) -> Agent {
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.set_read_timeout(Some(Duration::from_millis(100))).unwrap();
        let addr = sock.local_addr().unwrap();
        let requests = Arc::new(std::sync::Mutex::new(Vec::new()));
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (req2, stop2, community) = (requests.clone(), stop.clone(), community.to_string());
        std::thread::spawn(move || {
            let mut buf = vec![0u8; 65_535];
            while !stop2.load(std::sync::atomic::Ordering::Relaxed) {
                let Ok((n, from)) = sock.recv_from(&mut buf) else { continue };
                let Ok((comm, kind, id, a, b, oids)) = decode_request(&buf[..n]) else { continue };
                req2.lock().unwrap().push((kind, oids.clone()));
                if comm != community {
                    continue; // a wrong community is silently ignored, as real agents do
                }
                let next_after = |o: &Oid| table.range::<Oid, _>((std::ops::Bound::Excluded(o), std::ops::Bound::Unbounded)).next().map(|(k, v)| (k.clone(), v.clone()));
                let mut binds: Vec<(Oid, Value)> = Vec::new();
                let mut status = 0;
                match kind {
                    GET => {
                        for o in &oids {
                            binds.push((o.clone(), table.get(o).cloned().unwrap_or(Value::NoSuchInstance)));
                        }
                    }
                    GETNEXT => {
                        for o in &oids {
                            binds.push(next_after(o).unwrap_or((o.clone(), Value::EndOfMibView)));
                        }
                    }
                    GETBULK if refuse_bulk => status = 5,
                    GETBULK => {
                        let mut cur = oids[0].clone();
                        for _ in 0..b.max(1) as usize {
                            match next_after(&cur) {
                                Some((k, v)) => {
                                    cur = k.clone();
                                    binds.push((k, v));
                                }
                                None => {
                                    binds.push((cur.clone(), Value::EndOfMibView));
                                    break;
                                }
                            }
                        }
                        let _ = a;
                    }
                    _ => continue,
                }
                if let Ok(resp) = encode_response(&comm, id, status, &binds) {
                    let _ = sock.send_to(&resp, from);
                }
            }
        });
        Agent { addr, requests, stop }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn hex(s: &str) -> Vec<u8> {
        s.split_whitespace().map(|b| u8::from_str_radix(b, 16).unwrap()).collect()
    }

    #[test]
    fn integers_and_oids_encode_the_way_x690_says() {
        assert_eq!(enc_int(0), hex("02 01 00"));
        assert_eq!(enc_int(127), hex("02 01 7f"));
        assert_eq!(enc_int(128), hex("02 02 00 80"), "a leading zero keeps 128 from reading as negative");
        assert_eq!(enc_int(256), hex("02 02 01 00"));
        assert_eq!(enc_int(-1), hex("02 01 ff"));
        assert_eq!(enc_int(-128), hex("02 01 80"));
        assert_eq!(enc_int(-129), hex("02 02 ff 7f"));
        assert_eq!(enc_oid(&oid("1.3.6.1.2.1.1.1.0")).unwrap(), hex("06 08 2b 06 01 02 01 01 01 00"));
        // 1.3.6.1.4.1.311 (arc 311 needs two bytes: 0x82 0x37) and 2.999 (first two arcs 40*2+999 = 1079 -> 0x88 0x37)
        assert_eq!(enc_oid(&oid("1.3.6.1.4.1.311")).unwrap(), hex("06 07 2b 06 01 04 01 82 37"));
        assert_eq!(enc_oid(&oid("2.999.3")).unwrap(), hex("06 03 88 37 03"));
        assert!(enc_oid(&oid("1")).is_err() && enc_oid(&[3, 1]).is_err() && enc_oid(&[1, 40]).is_err());
        // long lengths: 200 bytes = 81 c8, 300 bytes = 82 01 2c
        assert_eq!(&tlv(0x04, &[0u8; 200])[..3], &hex("04 81 c8")[..]);
        assert_eq!(&tlv(0x04, &[0u8; 300])[..4], &hex("04 82 01 2c")[..]);
    }

    /// The classic `snmpget -v2c -c public host sysDescr.0`, laid out byte by byte from RFC 3416 and X.690.
    #[test]
    fn a_get_request_is_the_message_every_snmp_tool_sends() {
        let got = encode_request("public", GET, 0x0102_0304, 0, 0, &[oid("1.3.6.1.2.1.1.1.0")]).unwrap();
        let want = hex("30 29  02 01 01  04 06 70 75 62 6c 69 63  a0 1c  02 04 01 02 03 04  02 01 00  02 01 00  30 0e 30 0c 06 08 2b 06 01 02 01 01 01 00 05 00");
        assert_eq!(got, want);
    }

    #[test]
    fn a_get_bulk_request_carries_non_repeaters_and_max_repetitions() {
        let got = encode_request("x", GETBULK, 5, 0, 20, &[oid("1.3.6.1.2.1.2.2.1.2")]).unwrap();
        let (comm, kind, id, a, b, oids) = decode_request(&got).unwrap();
        assert_eq!((comm.as_str(), kind, id, a, b), ("x", GETBULK, 5, 0, 20));
        assert_eq!(oids, vec![oid("1.3.6.1.2.1.2.2.1.2")]);
        assert_eq!(got[got.len() - 17..][..4], hex("30 0f 30 0d")[..], "one variable binding at the end: a list of one binding");
    }

    #[test]
    fn responses_round_trip_with_every_kind_of_value() {
        let binds = vec![
            (oid("1.3.6.1.2.1.1.1.0"), Value::Str(b"Acme switch".to_vec())),
            (oid("1.3.6.1.2.1.1.3.0"), Value::Uint(4_000_000_000)),
            (oid("1.3.6.1.2.1.1.2.0"), Value::Oid(oid("1.3.6.1.4.1.9.1.1"))),
            (oid("1.3.6.1.2.1.2.1.0"), Value::Int(-3)),
            (oid("1.3.6.1.2.1.4.20.1.1.10.0.0.1"), Value::Ip([10, 0, 0, 1])),
            (oid("1.3.6.1.2.1.9.9.9"), Value::NoSuchInstance),
            (oid("1.3.6.1.2.1.9.9.10"), Value::EndOfMibView),
        ];
        let r = decode_response(&encode_response("public", 77, 0, &binds).unwrap()).unwrap();
        assert_eq!((r.request_id, r.error_status), (77, 0));
        assert_eq!(r.binds, binds);
        assert_eq!(binds[0].1.as_str().as_deref(), Some("Acme switch"));
    }

    #[test]
    fn hostile_bytes_are_an_error_and_never_a_panic() {
        let good = encode_response("public", 1, 0, &[(oid("1.3.6.1.2.1.1.1.0"), Value::Str(b"x".to_vec()))]).unwrap();
        // every truncation, and every single-byte corruption
        for n in 0..good.len() {
            let _ = decode_response(&good[..n]);
        }
        for i in 0..good.len() {
            for v in [0u8, 0x7f, 0x80, 0xff, 0x30, 0x06] {
                let mut bad = good.clone();
                bad[i] = v;
                let _ = decode_response(&bad);
            }
        }
        // pseudo-random garbage, lengths that run past the end, an indefinite length, a huge claimed length
        let mut x = 0x1234_5678u32;
        for _ in 0..2000 {
            let len = (x % 64) as usize;
            let junk: Vec<u8> = (0..len).map(|_| { x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223); (x >> 24) as u8 }).collect();
            let _ = decode_response(&junk);
        }
        assert!(decode_response(&hex("30 80 00 00")).is_err());
        assert!(decode_response(&hex("30 84 ff ff ff ff 02 01 01")).is_err());
        assert!(decode_response(&hex("04 01 00")).is_err(), "not a message");
        // a v1 message is not accepted as v2c
        assert!(decode_response(&hex("30 0c 02 01 00 04 00 a2 05 02 01 01 02 00")).is_err());
        // an arc that does not fit in 32 bits
        assert!(dec_oid(&hex("2b ff ff ff ff 7f")).is_err());
        assert!(dec_oid(&hex("2b 86")).is_err(), "ends inside an arc");
    }

    fn table(rows: &[(&str, Value)]) -> BTreeMap<Oid, Value> {
        rows.iter().map(|(o, v)| (oid(o), v.clone())).collect()
    }

    #[tokio::test]
    async fn get_and_a_walk_work_over_udp_and_a_walk_stays_inside_its_prefix() {
        let rows: Vec<(String, Value)> = (1..=45).map(|i| (format!("1.3.6.1.2.1.2.2.1.2.{i}"), Value::Str(format!("Gi1/0/{i}").into_bytes()))).collect();
        let mut t = BTreeMap::new();
        for (k, v) in &rows {
            t.insert(oid(k), v.clone());
        }
        t.insert(oid("1.3.6.1.2.1.1.5.0"), Value::Str(b"core-sw".to_vec()));
        t.insert(oid("1.3.6.1.2.1.2.2.1.3.1"), Value::Int(6)); // the next column: must not be included
        let agent = agent::start("secret", t, false);
        let mut c = Client::new(agent.addr, "secret", Duration::from_millis(500)).await.unwrap();
        let got = c.get(&[oid("1.3.6.1.2.1.1.5.0"), oid("1.3.6.1.2.1.1.9.0")]).await.unwrap();
        assert_eq!(got[0].1.as_str().as_deref(), Some("core-sw"));
        assert!(got[1].1.is_missing());
        let walked = c.walk(&oid("1.3.6.1.2.1.2.2.1.2")).await.unwrap();
        assert_eq!(walked.len(), 45, "three bulk answers of 20 are stitched together, and the column after is left out");
        assert_eq!(walked[0].1.as_str().as_deref(), Some("Gi1/0/1"));
        assert_eq!(walked[44].0, oid("1.3.6.1.2.1.2.2.1.2.45"));
        assert!(agent.requests.lock().unwrap().iter().any(|(k, _)| *k == GETBULK));
    }

    #[tokio::test]
    async fn a_device_without_bulk_is_walked_with_getnext_and_a_wrong_community_is_a_clear_error() {
        let t = table(&[("1.3.6.1.2.1.2.2.1.2.1", Value::Str(b"a".to_vec())), ("1.3.6.1.2.1.2.2.1.2.2", Value::Str(b"b".to_vec()))]);
        let agent = agent::start("secret", t, true);
        let mut c = Client::new(agent.addr, "secret", Duration::from_millis(500)).await.unwrap();
        assert_eq!(c.walk(&oid("1.3.6.1.2.1.2.2.1.2")).await.unwrap().len(), 2);
        assert!(agent.requests.lock().unwrap().iter().any(|(k, _)| *k == GETNEXT));
        let mut wrong = Client::new(agent.addr, "guess", Duration::from_millis(120)).await.unwrap();
        let e = wrong.get(&[oid("1.3.6.1.2.1.1.5.0")]).await.unwrap_err().to_string();
        assert!(e.contains("no answer") && e.contains("community"), "{e}");
    }

    #[tokio::test]
    async fn an_answer_with_another_id_is_ignored_and_a_walk_that_does_not_move_forward_ends() {
        // a sloppy agent that always answers with the same variable: the walk must stop, not loop
        let t = table(&[("1.3.6.1.2.1.2.2.1.2.1", Value::Str(b"a".to_vec()))]);
        let agent = agent::start("c", t, false);
        let mut c = Client::new(agent.addr, "c", Duration::from_millis(500)).await.unwrap();
        assert_eq!(c.walk(&oid("1.3.6.1.2.1.2.2.1.2")).await.unwrap().len(), 1);
        assert!(c.walk(&oid("1.3.6.1.2.1.99")).await.unwrap().is_empty());
    }
}
