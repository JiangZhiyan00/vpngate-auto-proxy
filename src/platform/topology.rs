//! 管理启停通知的有界接口材料解析；不执行远端命令或配置网络。
use std::{collections::BTreeSet, io, net::Ipv4Addr};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InterfaceTopology {
    PointToPoint { peer: Ipv4Addr },
    Subnet { netmask: Ipv4Addr },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InterfaceAssignment {
    name: String,
    local: Ipv4Addr,
    topology: InterfaceTopology,
    mtu: u16,
}
impl InterfaceAssignment {
    pub fn interface_name(&self) -> &str {
        &self.name
    }
    pub fn local_address(&self) -> Ipv4Addr {
        self.local
    }
    pub fn topology(&self) -> InterfaceTopology {
        self.topology
    }
    pub fn mtu(&self) -> u16 {
        self.mtu
    }
}

#[derive(Default)]
pub(crate) struct AssignmentParser {
    started: bool,
    finished: bool,
    bytes: usize,
    keys: BTreeSet<String>,
    name: Option<String>,
    dev_type: Option<String>,
    local: Option<Ipv4Addr>,
    peer: Option<Ipv4Addr>,
    netmask: Option<Ipv4Addr>,
    mtu: Option<u16>,
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn unicast(value: &str) -> io::Result<Ipv4Addr> {
    let address = value
        .parse::<Ipv4Addr>()
        .map_err(|_| invalid("接口地址不是有效四版地址"))?;
    let octets = address.octets();
    if octets[0] == 0 || octets[0] == 127 || octets[0] >= 224 || octets[..2] == [169, 254] {
        return Err(invalid("接口地址不是可用单播地址"));
    }
    Ok(address)
}

fn prefix(mask: Ipv4Addr) -> io::Result<u32> {
    let bits = u32::from(mask);
    let prefix = bits.leading_ones();
    if prefix == 0 || bits != u32::MAX << (32 - prefix) {
        return Err(invalid("接口掩码不连续或范围无效"));
    }
    Ok(prefix)
}

impl AssignmentParser {
    pub(crate) fn in_frame(&self) -> bool {
        self.started && !self.finished
    }
    pub(crate) fn consume(&mut self, line: &str) -> io::Result<Option<InterfaceAssignment>> {
        if self.finished || line.len() > 4096 || line.chars().any(char::is_control) {
            return Err(invalid("接口材料记录无效或重复"));
        }
        self.bytes = self
            .bytes
            .checked_add(line.len() + 1)
            .ok_or_else(|| invalid("接口材料总量溢出"))?;
        if self.bytes > 65536 {
            return Err(invalid("接口材料总量超限"));
        }
        if line == ">UPDOWN:UP" {
            if self.started {
                return Err(invalid("接口启用通知重复"));
            }
            self.started = true;
            return Ok(None);
        }
        if !self.started {
            return Err(invalid("接口环境材料早于启用通知"));
        }
        let field = line
            .strip_prefix(">UPDOWN:ENV,")
            .ok_or_else(|| invalid("接口材料提前结束或报告关闭"))?;
        if field == "END" {
            self.finished = true;
            return self.finish().map(Some);
        }
        let (key, value) = field
            .split_once('=')
            .ok_or_else(|| invalid("接口环境字段格式无效"))?;
        if key.is_empty()
            || key.len() > 128
            || !key
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
            || self.keys.len() >= 256
            || !self.keys.insert(key.to_owned())
        {
            return Err(invalid("接口环境字段重复、无效或数量超限"));
        }
        // 未使用的环境值不保存、不输出；通知可能包含认证或证书材料。
        match key {
            "dev" => {
                let digits = value
                    .strip_prefix("utun")
                    .ok_or_else(|| invalid("接口材料名称无效"))?;
                if digits.is_empty()
                    || value.len() >= nix::libc::IFNAMSIZ
                    || !digits.bytes().all(|byte| byte.is_ascii_digit())
                {
                    return Err(invalid("接口材料名称无效"));
                }
                self.name = Some(value.to_owned());
            }
            "dev_type" => {
                if value != "tun" {
                    return Err(invalid("接口材料类型不受支持"));
                }
                self.dev_type = Some(value.to_owned());
            }
            "ifconfig_local" => self.local = Some(unicast(value)?),
            "ifconfig_remote" => self.peer = Some(unicast(value)?),
            "ifconfig_netmask" => {
                let mask = value.parse().map_err(|_| invalid("接口掩码格式无效"))?;
                prefix(mask)?;
                self.netmask = Some(mask);
            }
            "tun_mtu" => {
                let mtu = value
                    .parse::<u16>()
                    .ok()
                    .filter(|mtu| *mtu >= 576)
                    .filter(|_| {
                        !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit())
                    })
                    .ok_or_else(|| invalid("接口最大传输单元无效"))?;
                self.mtu = Some(mtu);
            }
            _ => {}
        }
        Ok(None)
    }

    fn finish(&mut self) -> io::Result<InterfaceAssignment> {
        let local = self.local.ok_or_else(|| invalid("接口材料缺少本地地址"))?;
        let topology = match (self.peer, self.netmask) {
            (Some(peer), None) if peer != local => InterfaceTopology::PointToPoint { peer },
            (None, Some(netmask)) => {
                if prefix(netmask)? <= 30 {
                    let host = u32::from(local) & !u32::from(netmask);
                    if host == 0 || host == !u32::from(netmask) {
                        return Err(invalid("接口本地地址是子网或广播地址"));
                    }
                }
                InterfaceTopology::Subnet { netmask }
            }
            _ => return Err(invalid("接口拓扑材料缺失、冲突或对端与本地相同")),
        };
        if self.dev_type.as_deref() != Some("tun") {
            return Err(invalid("接口材料缺少类型"));
        }
        Ok(InterfaceAssignment {
            name: self
                .name
                .take()
                .ok_or_else(|| invalid("接口材料缺少名称"))?,
            local,
            topology,
            mtu: self
                .mtu
                .ok_or_else(|| invalid("接口材料缺少最大传输单元"))?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fields() -> Vec<String> {
        [
            "dev=utun42",
            "dev_type=tun",
            "tun_mtu=1500",
            "ifconfig_local=10.231.66.2",
            "ifconfig_remote=10.231.66.1",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    }

    fn parse(fields: &[String]) -> io::Result<InterfaceAssignment> {
        let mut parser = AssignmentParser::default();
        parser.consume(">UPDOWN:UP")?;
        for field in fields {
            parser.consume(&format!(">UPDOWN:ENV,{field}"))?;
        }
        parser
            .consume(">UPDOWN:ENV,END")?
            .ok_or_else(|| invalid("测试材料未交付"))
    }

    #[test]
    fn complete_interface_frame_distinguishes_peer_from_subnet_mask() {
        for (field, topology) in [
            (
                "ifconfig_remote=10.231.66.1",
                InterfaceTopology::PointToPoint {
                    peer: "10.231.66.1".parse().unwrap(),
                },
            ),
            (
                "ifconfig_netmask=255.255.255.0",
                InterfaceTopology::Subnet {
                    netmask: "255.255.255.0".parse().unwrap(),
                },
            ),
        ] {
            let mut parser = AssignmentParser::default();
            for line in [
                ">UPDOWN:UP".to_owned(),
                ">UPDOWN:ENV,dev=utun42".to_owned(),
                ">UPDOWN:ENV,dev_type=tun".to_owned(),
                ">UPDOWN:ENV,tun_mtu=1500".to_owned(),
                ">UPDOWN:ENV,ifconfig_local=10.231.66.2".to_owned(),
                format!(">UPDOWN:ENV,{field}"),
            ] {
                assert!(parser.consume(&line).unwrap().is_none());
            }
            let assignment = parser.consume(">UPDOWN:ENV,END").unwrap().unwrap();
            assert_eq!(assignment.interface_name(), "utun42");
            assert_eq!(
                assignment.local_address(),
                "10.231.66.2".parse::<Ipv4Addr>().unwrap()
            );
            assert_eq!(assignment.topology(), topology);
            assert_eq!(assignment.mtu(), 1500);
        }
    }

    #[test]
    fn interface_material_requires_every_field_and_one_topology() {
        for index in 0..fields().len() {
            let mut sample = fields();
            sample.remove(index);
            assert!(parse(&sample).is_err());
        }
        let mut sample = fields();
        sample.push("ifconfig_netmask=255.255.255.0".to_owned());
        assert!(parse(&sample).is_err());
        let mut sample = fields();
        sample[4] = "ifconfig_remote=10.231.66.2".to_owned();
        assert!(parse(&sample).is_err());
    }

    #[test]
    fn duplicate_fields_are_refused_without_echoing_environment_values() {
        for field in fields()
            .into_iter()
            .chain(["password=private-test-value".to_owned()])
        {
            let mut sample = fields();
            if field.starts_with("password=") {
                sample.push(field.clone());
            }
            sample.push(field);
            let error = parse(&sample).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            assert!(!error.to_string().contains("private-test-value"));
        }
        let mut sample = fields();
        sample.push("unknown=private-test-value=a,b".to_owned());
        assert_eq!(parse(&sample).unwrap(), parse(&fields()).unwrap());
    }

    #[test]
    fn unusable_addresses_and_noncontiguous_masks_are_refused() {
        for value in [
            "0.1.2.3",
            "127.0.0.2",
            "169.254.1.2",
            "224.0.0.1",
            "255.255.255.255",
            "::1",
            "10.0.0.1/24",
        ] {
            for index in [3, 4] {
                let mut sample = fields();
                let key = if index == 3 {
                    "ifconfig_local"
                } else {
                    "ifconfig_remote"
                };
                sample[index] = format!("{key}={value}");
                assert!(parse(&sample).is_err(), "不可用地址被接纳");
            }
        }
        for mask in ["0.0.0.0", "255.0.255.0", "255.255.255.1", "bad"] {
            let mut sample = fields();
            sample[4] = format!("ifconfig_netmask={mask}");
            assert!(parse(&sample).is_err());
        }
        for local in ["10.231.66.0", "10.231.66.255"] {
            let mut sample = fields();
            sample[3] = format!("ifconfig_local={local}");
            sample[4] = "ifconfig_netmask=255.255.255.0".to_owned();
            assert!(parse(&sample).is_err());
        }
        for (local, mask) in [
            ("10.231.66.2", "255.255.255.254"),
            ("10.231.66.3", "255.255.255.254"),
            ("10.231.66.2", "255.255.255.255"),
        ] {
            let mut sample = fields();
            sample[3] = format!("ifconfig_local={local}");
            sample[4] = format!("ifconfig_netmask={mask}");
            assert!(parse(&sample).is_ok());
        }
    }

    #[test]
    fn names_device_type_mtu_and_control_injection_are_refused() {
        for (index, field) in [
            (0, "dev=lo0"),
            (0, "dev=utun"),
            (0, "dev=utun1;up"),
            (0, "dev=utun123456789012"),
            (1, "dev_type=tap"),
            (2, "tun_mtu=575"),
            (2, "tun_mtu=65536"),
            (2, "tun_mtu=+1500"),
            (2, "tun_mtu=1500 "),
            (3, "ifconfig_local=10.0.0.2\n>UPDOWN:ENV,END"),
        ] {
            let mut sample = fields();
            sample[index] = field.to_owned();
            assert!(parse(&sample).is_err());
        }
        for mtu in [576, 65535] {
            let mut sample = fields();
            sample[2] = format!("tun_mtu={mtu}");
            assert_eq!(parse(&sample).unwrap().mtu(), mtu);
        }
    }

    #[test]
    fn material_frame_cannot_restart_end_early_or_continue_after_completion() {
        for line in [">UPDOWN:ENV,dev=utun42", ">UPDOWN:ENV,END", ">UPDOWN:DOWN"] {
            assert!(AssignmentParser::default().consume(line).is_err());
        }
        for line in [
            ">UPDOWN:UP",
            ">UPDOWN:DOWN",
            ">STATE:1,CONNECTED,SUCCESS",
            ">UPDOWN:ENV,END",
        ] {
            let mut parser = AssignmentParser::default();
            parser.consume(">UPDOWN:UP").unwrap();
            assert!(parser.in_frame());
            assert!(parser.consume(line).is_err());
        }
        let mut parser = AssignmentParser::default();
        parser.consume(">UPDOWN:UP").unwrap();
        for field in fields() {
            parser.consume(&format!(">UPDOWN:ENV,{field}")).unwrap();
        }
        parser.consume(">UPDOWN:ENV,END").unwrap();
        assert!(!parser.in_frame());
        assert!(parser.consume(">UPDOWN:UP").is_err());
    }

    #[test]
    fn interface_frame_line_field_count_and_total_bytes_are_bounded() {
        let mut parser = AssignmentParser::default();
        parser.consume(">UPDOWN:UP").unwrap();
        assert!(
            parser
                .consume(&format!(">UPDOWN:ENV,key={}", "a".repeat(4096)))
                .is_err()
        );
        let mut parser = AssignmentParser::default();
        parser.consume(">UPDOWN:UP").unwrap();
        for index in 0..256 {
            parser.consume(&format!(">UPDOWN:ENV,k{index}=a")).unwrap();
        }
        assert!(parser.consume(">UPDOWN:ENV,extra=a").is_err());
        let mut parser = AssignmentParser::default();
        parser.consume(">UPDOWN:UP").unwrap();
        let mut rejected = false;
        for index in 0..32 {
            if parser
                .consume(&format!(">UPDOWN:ENV,k{index}={}", "a".repeat(3000)))
                .is_err()
            {
                rejected = true;
                break;
            }
        }
        assert!(rejected, "不足字段上限时也必须拒绝累计超限");
    }
}
