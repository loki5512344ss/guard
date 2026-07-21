use std::time::Instant;

pub struct Ewma {
    value: f64,
    last: Instant,
    alpha: f64,
}

impl Ewma {
    pub fn new(alpha: f64) -> Self {
        Self {
            value: 0.0,
            last: Instant::now(),
            alpha,
        }
    }

    pub fn update(&mut self, sample: f64) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last).as_secs_f64();
        let steps = elapsed.max(1.0);
        let weight = (1.0 - self.alpha).powf(steps);
        self.value = self.value * weight + sample * (1.0 - weight);
        self.last = now;
    }

    pub fn value(&self) -> f64 {
        self.value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ewma_initial() {
        let ewma = Ewma::new(0.125);
        assert_eq!(ewma.value(), 0.0);
    }

    #[test]
    fn test_ewma_update() {
        let mut ewma = Ewma::new(1.0);
        ewma.update(100.0);
        assert!((ewma.value() - 100.0).abs() < 1.0);
    }

    #[test]
    fn test_ewma_convergence() {
        let mut ewma = Ewma::new(0.5);
        for _ in 0..10 {
            ewma.update(50.0);
        }
        assert!((ewma.value() - 50.0).abs() < 1.0);
    }
}
