use std::env;

use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

#[tokio::main(flavor = "current_thread")]
async fn main() -> std::io::Result<()> {
    let port: u16 = env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(9302);

    let listener = TcpListener::bind(("0.0.0.0", port)).await?;
    println!("listening on {port}");

    loop {
        let (mut sock, _) = listener.accept().await?;
        sock.set_nodelay(true)?;

        tokio::spawn(async move {
            let mut buf = [0u8; 8192];
            loop {
                let n = match sock.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(_) => break,
                };
                if sock.write_all(&buf[..n]).await.is_err() {
                    break;
                }
            }
        });
    }
}
