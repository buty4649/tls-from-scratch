use crate::error::Error;

use std::io::Write;

use byteorder::{ByteOrder, NativeEndian, WriteBytesExt};
use serde::{ser, Serialize};
use std::marker::PhantomData;

#[derive(Debug)]
pub struct Serializer<T: ByteOrder> {
    output: Vec<u8>,
    phantom_data: PhantomData<T>,
}

pub fn to_bytes<S, O>(value: &S) -> Result<Vec<u8>, Error>
where
    S: Serialize,
    O: ByteOrder,
{
    let mut serializer = Serializer::<O> {
        output: Vec::new(),
        phantom_data: PhantomData,
    };
    value.serialize(&mut serializer)?;
    Ok(serializer.output)
}

pub fn bytes_size<T>(value: &T) -> Result<usize, Error>
where
    T: Serialize,
{
    let mut serializer = Serializer::<NativeEndian> {
        output: Vec::new(),
        phantom_data: PhantomData,
    };
    value.serialize(&mut serializer)?;
    Ok(serializer.output.len())
}

impl<'a, O: ByteOrder> ser::Serializer for &'a mut Serializer<O> {
    type Ok = ();
    type Error = Error;

    type SerializeSeq = Self;
    type SerializeTuple = Self;
    type SerializeTupleStruct = Self;
    type SerializeTupleVariant = Self;
    type SerializeMap = Self;
    type SerializeStruct = Self;
    type SerializeStructVariant = Self;

    fn serialize_bool(self, v: bool) -> std::result::Result<Self::Ok, Self::Error> {
        self.output.write_u8(v as u8).unwrap();
        Ok(())
    }

    fn serialize_i8(self, v: i8) -> std::result::Result<Self::Ok, Self::Error> {
        self.output.write_i8(v).unwrap();
        Ok(())
    }

    fn serialize_i16(self, v: i16) -> std::result::Result<Self::Ok, Self::Error> {
        self.output.write_i16::<O>(v).unwrap();
        Ok(())
    }

    fn serialize_i32(self, v: i32) -> std::result::Result<Self::Ok, Self::Error> {
        self.output.write_i32::<O>(v).unwrap();
        Ok(())
    }

    fn serialize_i64(self, v: i64) -> std::result::Result<Self::Ok, Self::Error> {
        self.output.write_i64::<O>(v).unwrap();
        Ok(())
    }

    fn serialize_i128(self, v: i128) -> std::result::Result<Self::Ok, Self::Error> {
        self.output.write_i128::<O>(v).unwrap();
        Ok(())
    }

    fn serialize_u8(self, v: u8) -> std::result::Result<Self::Ok, Self::Error> {
        self.output.write_u8(v).unwrap();
        Ok(())
    }

    fn serialize_u16(self, v: u16) -> std::result::Result<Self::Ok, Self::Error> {
        self.output.write_u16::<O>(v).unwrap();
        Ok(())
    }

    fn serialize_u32(self, v: u32) -> std::result::Result<Self::Ok, Self::Error> {
        self.output.write_u32::<O>(v).unwrap();
        Ok(())
    }

    fn serialize_u64(self, v: u64) -> std::result::Result<Self::Ok, Self::Error> {
        self.output.write_u64::<O>(v).unwrap();
        Ok(())
    }

    fn serialize_u128(self, v: u128) -> std::result::Result<Self::Ok, Self::Error> {
        self.output.write_u128::<O>(v).unwrap();
        Ok(())
    }

    fn serialize_f32(self, v: f32) -> std::result::Result<Self::Ok, Self::Error> {
        self.output.write_f32::<O>(v).unwrap();
        Ok(())
    }

    fn serialize_f64(self, v: f64) -> std::result::Result<Self::Ok, Self::Error> {
        self.output.write_f64::<O>(v).unwrap();
        Ok(())
    }

    fn serialize_char(self, v: char) -> std::result::Result<Self::Ok, Self::Error> {
        self.output.write_u8(v as u8).unwrap();
        Ok(())
    }

    fn serialize_str(self, v: &str) -> std::result::Result<Self::Ok, Self::Error> {
        self.output.write_all(v.as_bytes()).unwrap();
        Ok(())
    }

    fn serialize_bytes(self, v: &[u8]) -> std::result::Result<Self::Ok, Self::Error> {
        self.output.write_all(v).unwrap();
        Ok(())
    }

    fn serialize_none(self) -> std::result::Result<Self::Ok, Self::Error> {
        self.output.write_u8(0).unwrap();
        Ok(())
    }

    fn serialize_some<T: ?Sized>(self, value: &T) -> std::result::Result<Self::Ok, Self::Error>
    where
        T: ser::Serialize,
    {
        value.serialize(self)
    }

    fn serialize_unit(self) -> std::result::Result<Self::Ok, Self::Error> {
        Ok(())
    }

    fn serialize_unit_struct(
        self,
        _name: &'static str,
    ) -> std::result::Result<Self::Ok, Self::Error> {
        Ok(())
    }

    fn serialize_unit_variant(
        self,
        _name: &'static str,
        variant_index: u32,
        _variant: &'static str,
    ) -> std::result::Result<Self::Ok, Self::Error> {
        variant_index.serialize(self)
    }

    fn serialize_newtype_struct<T: ?Sized>(
        self,
        _name: &'static str,
        value: &T,
    ) -> std::result::Result<Self::Ok, Self::Error>
    where
        T: ser::Serialize,
    {
        value.serialize(self)
    }

    fn serialize_newtype_variant<T>(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        value: &T,
    ) -> std::result::Result<Self::Ok, Self::Error>
    where
        T: ?Sized + Serialize,
    {
        value.serialize(self)
    }

    fn serialize_seq(
        self,
        _len: Option<usize>,
    ) -> std::result::Result<Self::SerializeSeq, Self::Error> {
        Ok(self)
    }

    fn serialize_map(self, _len: Option<usize>) -> Result<Self::SerializeMap, Self::Error> {
        Ok(self)
    }

    fn serialize_struct(
        self,
        _name: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStruct, Self::Error> {
        Ok(self)
    }

    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStructVariant, Self::Error> {
        Ok(self)
    }

    fn serialize_tuple(self, _len: usize) -> Result<Self::SerializeTuple, Self::Error> {
        Ok(self)
    }

    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleStruct, Self::Error> {
        Ok(self)
    }

    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleVariant, Self::Error> {
        Ok(self)
    }
}

impl<'a, O: ByteOrder> ser::SerializeSeq for &'a mut Serializer<O> {
    type Ok = ();
    type Error = Error;

    fn serialize_element<T>(&mut self, value: &T) -> std::result::Result<(), Self::Error>
    where
        T: ?Sized + Serialize,
    {
        value.serialize(&mut **self)
    }

    fn end(self) -> std::result::Result<Self::Ok, Self::Error> {
        Ok(())
    }
}

impl<'a, O: ByteOrder> ser::SerializeTuple for &'a mut Serializer<O> {
    type Ok = ();
    type Error = Error;

    fn serialize_element<T>(&mut self, value: &T) -> std::result::Result<(), Self::Error>
    where
        T: ?Sized + Serialize,
    {
        value.serialize(&mut **self)
    }

    fn end(self) -> std::result::Result<Self::Ok, Self::Error> {
        Ok(())
    }
}

impl<'a, O: ByteOrder> ser::SerializeTupleStruct for &'a mut Serializer<O> {
    type Ok = ();
    type Error = Error;

    fn serialize_field<T>(&mut self, value: &T) -> std::result::Result<(), Self::Error>
    where
        T: ?Sized + Serialize,
    {
        value.serialize(&mut **self)
    }

    fn end(self) -> std::result::Result<Self::Ok, Self::Error> {
        Ok(())
    }
}

impl<'a, O: ByteOrder> ser::SerializeTupleVariant for &'a mut Serializer<O> {
    type Ok = ();
    type Error = Error;

    fn serialize_field<T>(&mut self, value: &T) -> std::result::Result<(), Self::Error>
    where
        T: ?Sized + Serialize,
    {
        value.serialize(&mut **self)
    }

    fn end(self) -> std::result::Result<Self::Ok, Self::Error> {
        Ok(())
    }
}

impl<'a, O: ByteOrder> ser::SerializeMap for &'a mut Serializer<O> {
    type Ok = ();
    type Error = Error;

    fn serialize_key<T>(&mut self, key: &T) -> std::result::Result<(), Self::Error>
    where
        T: ?Sized + Serialize,
    {
        key.serialize(&mut **self)
    }

    fn serialize_value<T>(&mut self, value: &T) -> std::result::Result<(), Self::Error>
    where
        T: ?Sized + Serialize,
    {
        value.serialize(&mut **self)
    }

    fn end(self) -> std::result::Result<Self::Ok, Self::Error> {
        Ok(())
    }
}

impl<'a, O: ByteOrder> ser::SerializeStruct for &'a mut Serializer<O> {
    type Ok = ();
    type Error = Error;

    fn serialize_field<T>(
        &mut self,
        _key: &'static str,
        value: &T,
    ) -> std::result::Result<(), Self::Error>
    where
        T: ?Sized + Serialize,
    {
        value.serialize(&mut **self)?;
        Ok(())
    }

    fn end(self) -> std::result::Result<Self::Ok, Self::Error> {
        Ok(())
    }
}

impl<'a, O: ByteOrder> ser::SerializeStructVariant for &'a mut Serializer<O> {
    type Ok = ();
    type Error = Error;

    fn serialize_field<T>(
        &mut self,
        _key: &'static str,
        value: &T,
    ) -> std::result::Result<(), Self::Error>
    where
        T: ?Sized + Serialize,
    {
        value.serialize(&mut **self)?;
        Ok(())
    }

    fn end(self) -> std::result::Result<(), Self::Error> {
        Ok(())
    }
}
