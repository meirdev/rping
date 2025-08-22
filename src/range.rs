use std::str::FromStr;

fn parse_range<T: std::str::FromStr + std::cmp::PartialOrd + std::fmt::Display + Copy>(
    input: &str,
) -> Result<std::ops::RangeInclusive<T>, String> {
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
pub enum Range<T> {
    Single(T),
    Range(std::ops::RangeInclusive<T>),
}

impl<T: std::str::FromStr + std::cmp::PartialOrd + std::fmt::Display + Copy> FromStr for Range<T> {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.contains('-') {
            parse_range::<T>(s)
                .map(Range::Range)
                .map_err(|e| e.to_string())
        } else {
            T::from_str(s)
                .map(Range::Single)
                .map_err(|_| "Invalid value".to_string())
        }
    }
}
