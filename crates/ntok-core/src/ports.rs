use crate::error::{Error, Result};

/// Well-known ports, roughly ordered by prevalence (nmap top-ports order, truncated).
const TOP_PORTS: &[u16] = &[
    80, 443, 22, 21, 25, 3389, 110, 445, 139, 143, 53, 135, 3306, 8080, 1723, 111, 995, 993, 5900,
    1025, 587, 8888, 199, 1720, 465, 548, 113, 81, 6001, 10000, 514, 5060, 179, 1026, 2000, 8443,
    8000, 554, 26, 1433, 2001, 515, 8008, 1027, 5666, 646, 5000, 5631, 631, 8081, 2049, 88, 79,
    5800, 106, 2121, 1110, 6000, 513, 990, 5357, 427, 543, 544, 5101, 144, 7, 389, 8009, 3128, 444,
    9999, 5009, 7070, 5190, 3000, 5432, 1900, 13, 1029, 9, 873, 1755, 4899, 9100, 119, 37, 1000,
    3001, 5001, 9090, 1024, 1801, 5050, 1352, 6379, 27017, 9200, 11211, 2375, 5985, 161, 1521,
    2222, 4848, 5984, 9000, 9418, 5601, 15672, 61616, 2181, 10050, 3260, 8020, 4040, 7001, 9001,
    2379, 8500, 4369, 5672, 7547, 2082,
];

/// Parse a port specification: `"22,80,443"`, `"1-1024"`, `"top:100"`, `"all"`.
/// Tokens may be mixed in one comma-separated list.
pub fn parse_ports(spec: &str) -> Result<Vec<u16>> {
    let mut out: Vec<u16> = Vec::new();
    for tok in spec.split(',') {
        let tok = tok.trim();
        if tok.is_empty() {
            continue;
        }
        if let Some(rest) = tok.strip_prefix("top:") {
            let n: usize = rest
                .trim()
                .parse()
                .map_err(|_| Error::BadPorts(tok.into()))?;
            out.extend_from_slice(&TOP_PORTS[..n.min(TOP_PORTS.len())]);
        } else if tok == "all" {
            out.extend(1u16..=u16::MAX);
        } else if let Some((a, b)) = tok.split_once('-') {
            let lo: u16 = a.trim().parse().map_err(|_| Error::BadPorts(tok.into()))?;
            let hi: u16 = b.trim().parse().map_err(|_| Error::BadPorts(tok.into()))?;
            if lo == 0 || hi < lo {
                return Err(Error::BadPorts(tok.into()));
            }
            out.extend(lo..=hi);
        } else {
            let p: u16 = tok.parse().map_err(|_| Error::BadPorts(tok.into()))?;
            if p == 0 {
                return Err(Error::BadPorts(tok.into()));
            }
            out.push(p);
        }
    }
    out.sort_unstable();
    out.dedup();
    if out.is_empty() {
        return Err(Error::BadPorts(spec.into()));
    }
    Ok(out)
}

/// Default port set when none is given (~top 120).
pub fn default_ports() -> Vec<u16> {
    TOP_PORTS.to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_lists_and_ranges() {
        assert_eq!(parse_ports("22,80-82").unwrap(), vec![22, 80, 81, 82]);
        assert_eq!(parse_ports("443").unwrap(), vec![443]);
    }

    #[test]
    fn dedups_and_sorts() {
        assert_eq!(parse_ports("443,80,443").unwrap(), vec![80, 443]);
    }

    #[test]
    fn top_and_all() {
        assert_eq!(parse_ports("top:3").unwrap(), vec![22, 80, 443]);
        assert_eq!(parse_ports("all").unwrap().len(), 65535);
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse_ports("abc").is_err());
        assert!(parse_ports("0").is_err());
        assert!(parse_ports("90-10").is_err());
        assert!(parse_ports("").is_err());
    }
}
