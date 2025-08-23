use std::fmt::Display;
use std::ops::RangeInclusive;
use std::str::FromStr;

use rand::Rng;
use rand::distr::uniform::SampleUniform;
use rand::rngs::StdRng;

fn parse_range<T: FromStr + PartialOrd + Display + Copy + Clone + SampleUniform>(
    input: &str,
) -> Result<RangeInclusive<T>, String> {
    let parts: Vec<&str> = input.split('-').collect();
    if parts.len() != 2 {
        return Err("Invalid range format. Use 'start-end'.".to_string());
    }

    let start = parts[0]
        .parse::<T>()
        .map_err(|_| "Invalid start".to_string())?;
    let end = parts[1]
        .parse::<T>()
        .map_err(|_| "Invalid end".to_string())?;

    if start > end {
        return Err("Start cannot be greater than end".to_string());
    }

    Ok(start..=end)
}

#[derive(Debug, Clone)]
pub struct Range<T>(pub RangeInclusive<T>);

impl<T: FromStr + PartialOrd + Display + Copy + Clone + SampleUniform> Range<T> {
    pub fn new(start: T, end: T) -> Self {
        Range(start..=end)
    }

    pub fn get_random_value(&self, rng: &mut StdRng) -> T {
        rng.random_range(self.0.start().clone()..=self.0.end().clone())
    }
}

impl<T: FromStr + PartialOrd + Display + Copy + Clone + SampleUniform> FromStr for Range<T> {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.contains('-') {
            parse_range::<T>(s)
                .map(|i| Range(i))
                .map_err(|e| e.to_string())
        } else {
            T::from_str(s)
                .map(|i| Range(i..=i))
                .map_err(|_| "Invalid value".to_string())
        }
    }
}
