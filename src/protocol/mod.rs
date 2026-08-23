use std::future::Future;
use std::pin::Pin;
use tokio::net::TcpStream;

/// Результат успешного protocol-handshake: адрес upstream-бэкенда,
/// на который нужно проксировать соединение.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Upstream {
    pub addr: String,
}

impl Upstream {
    #[must_use]
    pub fn new(addr: impl Into<String>) -> Self {
        Self { addr: addr.into() }
    }
}

/// Точка расширения платформы: реализация для конкретного L7-протокола.
///
/// Контракт минимальный: обработчик проводит handshake с клиентом
/// (чтение/запись в поток до момента, когда можно проксировать) и
/// возвращает целевой [`Upstream`]. Реализации поставляются фичами
/// (`--features protocol-http`, внешние plugin-крейты) — в ядре их нет.
///
/// Метод асинхронен через boxed future, чтобы трейт оставался
/// dyn-совместимым (`ProtocolRegistry` хранит `Box<dyn ProtocolHandler>`).
pub trait ProtocolHandler: Send + Sync {
    /// Имя протокола (для метрик, логов и реестра).
    fn name(&self) -> &'static str;

    /// Проводит handshake с клиентом и определяет upstream.
    ///
    /// # Errors
    /// Возвращает ошибку при невалидном клиентском потоке или отказе в доступе.
    fn handshake<'a>(
        &'a self,
        stream: &'a mut TcpStream,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<Upstream>> + Send + 'a>>;
}

/// Реестр скомпилированных протокольных обработчиков.
#[derive(Default)]
pub struct ProtocolRegistry {
    handlers: Vec<Box<dyn ProtocolHandler>>,
}

impl ProtocolRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, handler: Box<dyn ProtocolHandler>) {
        self.handlers.push(handler);
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.handlers.is_empty()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.handlers.len()
    }

    #[must_use]
    pub fn names(&self) -> Vec<&'static str> {
        self.handlers.iter().map(|h| h.name()).collect()
    }

    #[must_use]
    pub fn get(&self, name: &str) -> Option<&dyn ProtocolHandler> {
        self.handlers.iter().find(|h| h.name() == name).map(|h| h.as_ref())
    }

    /// Возвращает основной обработчик.
    ///
    /// # Errors
    /// Возвращает ошибку, если ни один протокол не скомпилирован —
    /// edge-нода обязана fail-fast на старте в этом случае.
    pub fn primary(&self) -> anyhow::Result<&dyn ProtocolHandler> {
        let Some(handler) = self.handlers.first() else {
            anyhow::bail!(
                "no protocol plugins compiled; build with --features protocol-http \
                 or link an external ProtocolHandler implementation"
            );
        };
        Ok(handler.as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct DummyHandler;

    impl ProtocolHandler for DummyHandler {
        fn name(&self) -> &'static str {
            "dummy"
        }

        fn handshake<'a>(
            &'a self,
            _stream: &'a mut TcpStream,
        ) -> Pin<Box<dyn Future<Output = anyhow::Result<Upstream>> + Send + 'a>> {
            Box::pin(async { Ok(Upstream::new("127.0.0.1:9000")) })
        }
    }

    #[test]
    fn empty_registry_fails_fast() {
        let registry = ProtocolRegistry::new();
        assert!(registry.is_empty());
        assert!(registry.primary().is_err());
    }

    #[test]
    fn registered_handler_is_resolvable() {
        let mut registry = ProtocolRegistry::new();
        registry.register(Box::new(DummyHandler));
        assert_eq!(registry.len(), 1);
        assert_eq!(registry.names(), vec!["dummy"]);
        assert!(registry.primary().is_ok());
        assert!(registry.get("dummy").is_some());
        assert!(registry.get("missing").is_none());
    }
}
