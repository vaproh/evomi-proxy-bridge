//! PAC auto-config: serves proxy.pac / wpad.dat so browsers can
//! auto-configure instead of manual proxy entry.

/// PAC body pointing at the given loopback port.
pub fn pac_body(port: u16) -> String {
    format!(
        "function FindProxyForURL(url, host) {{\n  return \"PROXY 127.0.0.1:{port}\";\n}}\n"
    )
}

pub fn pac_response(port: u16) -> Vec<u8> {
    let body = pac_body(port);
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/x-ns-proxy-autoconfig\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    )
    .into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pac_points_at_port() {
        let body = pac_body(8899);
        assert!(body.contains("PROXY 127.0.0.1:8899"));
    }
}
