use crate::errors::DkgError;
use std::io::{Cursor, Read};

fn error() -> DkgError {
    DkgError::DeserializationError("Input bytes too small or not valid".to_owned())
}

/// Extract u32 from the source [cursor]
pub fn read_u32(cursor: &mut Cursor<&[u8]>) -> Result<u32, DkgError> {
    let mut size_bytes = [0u8; 4];

    cursor.read_exact(&mut size_bytes).map_err(|_| error())?;
    let size = u32::from_le_bytes(size_bytes);
    Ok(size)
}

/// Extracts the vector of u8 from input source,
/// Expected
///  - first 4 bytes represent size of the vector
///  - the next bytes should be the actual vector data
pub fn read_vector(cursor: &mut Cursor<&[u8]>) -> Result<Vec<u8>, DkgError> {
    let size = read_u32(cursor)? as usize;
    let mut value = vec![0; size];
    cursor.read_exact(&mut value).map_err(|_| error())?;
    Ok(value)
}

/// Extracts the vector of u8 from input source,
/// Expected
///  - first 4 bytes represent size of the vector
///  - the next bytes should be the actual vector data
pub fn read_vector_of_vectors(cursor: &mut Cursor<&[u8]>) -> Result<Vec<Vec<u8>>, DkgError> {
    let size = read_u32(cursor)?;
    let mut value = Vec::new();
    for _ in 0..size {
        value.push(read_vector(cursor)?)
    }
    Ok(value)
}

/// Wrote u32 from the source [cursor]
pub fn write_u32(dest: &mut Vec<u8>, size: u32) {
    dest.append(&mut size.to_le_bytes().to_vec());
}

/// Write the [src] vector of u8 into [dest] in the following format.
///  - first 4 bytes represent size of the vector
///  - the next bytes are the actual vector data
pub fn write_vector(dest: &mut Vec<u8>, mut src: Vec<u8>) {
    write_u32(dest, src.len() as u32);
    dest.append(&mut src);
}

/// Write the [src] vector of u8 into [dest] in the following format.
///  - first 4 bytes represent size of the vector
///  - the next bytes are the actual vector data
pub fn write_vector_of_vector(dest: &mut Vec<u8>, src: Vec<Vec<u8>>) {
    write_u32(dest, src.len() as u32);
    for item in src {
        write_vector(dest, item)
    }
}

pub fn write_vector_u32(dest: &mut Vec<u8>, src: Vec<u32>) {
    write_u32(dest, src.len() as u32);
    for x in src{
        write_u32(dest, x)
    }
}

pub fn write_vector_of_vector_u32(dest: &mut Vec<u8>, src: Vec<Vec<u32>>) {
    write_u32(dest, src.len() as u32);
    for item in src {
        write_vector_u32(dest, item)
    }
}

pub fn read_vector_u32(cursor: &mut Cursor<&[u8]>) -> Result<Vec<u32>, DkgError> {
    let size = read_u32(cursor)? as usize;
    let mut vec = Vec::with_capacity(size);
    for _i in 0..size {
        let x = read_u32(cursor)?;
        vec.push(x);
    }
    Ok(vec)
}

pub fn read_vector_of_vectors_u32(cursor: &mut Cursor<&[u8]>) -> Result<Vec<Vec<u32>>, DkgError> {
    let size = read_u32(cursor)? as usize;
    let mut value = Vec::with_capacity(size);
    for _ in 0..size {
        value.push(read_vector_u32(cursor)?)
    }
    Ok(value)
}