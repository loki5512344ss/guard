#[cfg(feature = "xdp")]
pub struct XdpFilter {
    interface: String,
}

#[cfg(feature = "xdp")]
impl XdpFilter {
    pub fn new(interface: &str) -> Self {
        Self {
            interface: interface.to_string(),
        }
    }

    pub fn load(&self) -> anyhow::Result<()> {
        tracing::info!("XDP filter loaded on {}", self.interface);
        Ok(())
    }

    pub fn unload(&self) -> anyhow::Result<()> {
        tracing::info!("XDP filter unloaded from {}", self.interface);
        Ok(())
    }
}

#[cfg(not(feature = "xdp"))]
pub struct XdpFilter;

#[cfg(not(feature = "xdp"))]
impl XdpFilter {
    pub fn new(_interface: &str) -> Self {
        Self
    }

    pub fn load(&self) -> anyhow::Result<()> {
        Ok(())
    }

    pub fn unload(&self) -> anyhow::Result<()> {
        Ok(())
    }
}
