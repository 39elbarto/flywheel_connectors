fn main() {
    let url = url::Url::parse("http://[2001:db8::1]:8080").unwrap();
    let host = url.host_str().unwrap();
    println!("host_str: {}", host);
    let ip = host.parse::<std::net::IpAddr>();
    println!("parse ip: {:?}", ip);
}
