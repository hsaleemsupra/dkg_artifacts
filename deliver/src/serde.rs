use std::io::{Cursor, Read};
use crate::errors::DeliverError;

fn error() -> DeliverError {
    DeliverError::DeserializationError("Input bytes too small or not valid".to_owned())
}

/// Extract u32 from the source [cursor]
pub(crate) fn read_u32(cursor: &mut Cursor<&[u8]>) -> Result<u32, DeliverError> {
    let mut size_bytes = [0u8; 4];

    cursor.read_exact(&mut size_bytes).map_err(|_| error())?;
    let size = u32::from_le_bytes(size_bytes);
    Ok(size)
}

/// Extracts the vector of u8 from input source,
/// Expected
///  - first 4 bytes represent size of the vector
///  - the next bytes should be the actual vector data
pub fn read_vector(cursor: &mut Cursor<&[u8]>) -> Result<Vec<u8>, DeliverError> {
    let size = read_u32(cursor)? as usize;
    let mut value = vec![0; size];
    cursor.read_exact(&mut value).map_err(|_| error())?;
    Ok(value)
}


/// Wrote u32 from the source [cursor]
pub(crate) fn write_u32(dest: &mut Vec<u8>, size: u32) {
    dest.append(&mut size.to_le_bytes().to_vec());
}

/// Write the [src] vector of u8 into [dest] in the following format.
///  - first 4 bytes represent size of the vector
///  - the next bytes are the actual vector data
pub fn write_vector(dest: &mut Vec<u8>, mut src: Vec<u8>) {
    write_u32(dest, src.len() as u32);
    dest.append(&mut src);
}