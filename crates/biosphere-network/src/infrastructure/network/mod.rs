use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::net::TcpStream;

pub async fn check_tcp_port(
    target: IpAddr,
    port: u16,
    timeout_ms: u64,
) -> Result<bool, std::io::Error> {
    let addr = SocketAddr::new(target, port);
    let timeout = Duration::from_millis(timeout_ms);

    match tokio::time::timeout(timeout, TcpStream::connect(&addr)).await {
        Ok(Ok(_)) => Ok(true),
        Ok(Err(_)) => Ok(false),
        Err(_) => Ok(false),
    }
}

pub async fn check_tcp_port_fast(
    target: IpAddr,
    port: u16,
    timeout_ms: u64,
) -> Result<bool, std::io::Error> {
    let addr = SocketAddr::new(target, port);
    let timeout = Duration::from_millis((timeout_ms / 2).max(50));

    match tokio::time::timeout(timeout, TcpStream::connect(&addr)).await {
        Ok(Ok(_)) => Ok(true),
        Ok(Err(_)) => Ok(false),
        Err(_) => Ok(false),
    }
}

pub async fn resolve_hostname(hostname: &str) -> Result<IpAddr, std::io::Error> {
    use tokio::net::lookup_host;
    
    let addr = format!("{}:0", hostname);
    let mut addrs = lookup_host(&addr).await?;
    
    addrs.next()
        .map(|socket_addr| socket_addr.ip())
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("Could not resolve hostname: {}", hostname),
            )
        })
}

pub async fn resolve_hostname_all(hostname: &str) -> Result<Vec<IpAddr>, std::io::Error> {
    use tokio::net::lookup_host;
    
    let addr = format!("{}:0", hostname);
    let addrs = lookup_host(&addr).await?;
    
    let ips: Vec<IpAddr> = addrs.map(|socket_addr| socket_addr.ip()).collect();
    
    if ips.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("Could not resolve hostname: {}", hostname),
        ));
    }
    
    Ok(ips)
}
