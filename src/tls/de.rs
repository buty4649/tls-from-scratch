pub type IResult<'a, O> = nom::IResult<Buffer<'a>, O>;

#[derive(Debug, Clone)]
pub struct Buffer<'a> {
    data: &'a [u8],
    length: usize,
}

impl<'a> Buffer<'a> {
    pub fn new<U: nom::ToUsize>(data: &'a [u8], length: U) -> Self {
        let length = length.to_usize();
        Buffer { data, length }
    }

    pub fn length(&self) -> usize {
        self.length
    }
}

use nom::{
    bytes::complete::take as nom_take,
    error::Error as nomError,
    number::complete::{be_u16 as nom_be_u16, be_u32 as nom_be_u32, be_u8 as nom_be_u8},
};

pub fn be_u8(input: Buffer) -> IResult<u8> {
    if input.length < 1 {
        return Err(nom::Err::Error(nomError::new(
            input,
            nom::error::ErrorKind::Eof,
        )));
    }

    let (i, d) = nom_be_u8::<&[u8], nomError<&[u8]>>(input.data).unwrap();
    Ok((Buffer::new(i, input.length - 1), d))
}

pub fn be_u16(input: Buffer) -> IResult<u16> {
    if input.length < 2 {
        return Err(nom::Err::Error(nomError::new(
            input,
            nom::error::ErrorKind::Eof,
        )));
    }

    let (i, d) = nom_be_u16::<&[u8], nomError<&[u8]>>(input.data).unwrap();
    Ok((Buffer::new(i, input.length - 2), d))
}

pub fn be_u32(input: Buffer) -> IResult<u32> {
    if input.length < 2 {
        return Err(nom::Err::Error(nomError::new(
            input,
            nom::error::ErrorKind::Eof,
        )));
    }

    let (i, d) = nom_be_u32::<&[u8], nomError<&[u8]>>(input.data).unwrap();
    Ok((Buffer::new(i, input.length - 4), d))
}

pub fn take<C: nom::ToUsize>(input: Buffer, n: C) -> IResult<&[u8]> {
    let n = n.to_usize();
    let (i, d) = nom_take::<usize, &[u8], nomError<&[u8]>>(n)(input.data).unwrap();
    Ok((Buffer::new(i, input.length - n), d))
}
