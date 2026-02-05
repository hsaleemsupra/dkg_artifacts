use crate::MetricError;
use std::collections::HashMap;

pub type Tags = HashMap<String, String>;
pub type TagEntry = (String, String);

#[derive(Debug, Clone)]
pub enum MetricValue {
    Bool(bool),
    Int(i32),
    UInt(u32),
    Int64(i64),
    UInt64(u64),
    Usize(usize),
    Int128(i128),
    UInt128(u128),
    Float32(f32),
    Float64(f64),
    String(String),
}

impl MetricValue {
    pub fn update(&self, new_value: MetricValue) -> Result<Self, MetricError> {
        if self.index() == new_value.index() {
            Ok(new_value)
        } else {
            Err(MetricError::MetricValueTypeError(new_value))
        }
    }

    pub fn inc(&mut self, value: MetricValue) -> Result<(), MetricError> {
        if self.index() != value.index() {
            return Err(MetricError::MetricValueTypeError(value));
        }
        // TODO check overflow
        match self {
            MetricValue::Int(v) => *v += value.as_int().unwrap(),
            MetricValue::UInt(v) => *v += value.as_uint().unwrap(),
            MetricValue::Int64(v) => *v += value.as_int64().unwrap(),
            MetricValue::UInt64(v) => *v += value.as_uint64().unwrap(),
            MetricValue::Usize(v) => *v += value.as_usize().unwrap(),
            MetricValue::Int128(v) => *v += value.as_int128().unwrap(),
            MetricValue::UInt128(v) => *v += value.as_uint128().unwrap(),
            MetricValue::Float32(v) => *v += value.as_float32().unwrap(),
            MetricValue::Float64(v) => *v += value.as_float64().unwrap(),
            MetricValue::String(_) | MetricValue::Bool(_) => {
                return Err(MetricError::MetricUnsupportedOp(self.clone()))
            }
        }
        Ok(())
    }

    pub fn index(&self) -> u8 {
        match self {
            MetricValue::Bool(_) => 0,
            MetricValue::Int(_) => 1,
            MetricValue::UInt(_) => 2,
            MetricValue::Int64(_) => 3,
            MetricValue::UInt64(_) => 4,
            MetricValue::Usize(_) => 5,
            MetricValue::Int128(_) => 6,
            MetricValue::UInt128(_) => 7,
            MetricValue::Float32(_) => 8,
            MetricValue::Float64(_) => 9,
            MetricValue::String(_) => 10,
        }
    }

    pub fn as_bool(&self) -> Option<&bool> {
        match self {
            MetricValue::Bool(v) => Some(v),
            _ => None,
        }
    }
    pub fn as_string(&self) -> Option<&String> {
        match self {
            MetricValue::String(v) => Some(v),
            _ => None,
        }
    }
    pub fn as_int(&self) -> Option<&i32> {
        match self {
            MetricValue::Int(v) => Some(v),
            _ => None,
        }
    }
    pub fn as_uint(&self) -> Option<&u32> {
        match self {
            MetricValue::UInt(v) => Some(v),
            _ => None,
        }
    }
    pub fn as_int64(&self) -> Option<&i64> {
        match self {
            MetricValue::Int64(v) => Some(v),
            _ => None,
        }
    }
    pub fn as_uint64(&self) -> Option<&u64> {
        match self {
            MetricValue::UInt64(v) => Some(v),
            _ => None,
        }
    }
    pub fn as_int128(&self) -> Option<&i128> {
        match self {
            MetricValue::Int128(v) => Some(v),
            _ => None,
        }
    }
    pub fn as_uint128(&self) -> Option<&u128> {
        match self {
            MetricValue::UInt128(v) => Some(v),
            _ => None,
        }
    }
    pub fn as_usize(&self) -> Option<&usize> {
        match self {
            MetricValue::Usize(v) => Some(v),
            _ => None,
        }
    }
    pub fn as_float32(&self) -> Option<&f32> {
        match self {
            MetricValue::Float32(v) => Some(v),
            _ => None,
        }
    }
    pub fn as_float64(&self) -> Option<&f64> {
        match self {
            MetricValue::Float64(v) => Some(v),
            _ => None,
        }
    }
}
