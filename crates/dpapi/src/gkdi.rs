use std::io::{Read, Write};

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;

use crate::rpc::{Decode, Encode};
use crate::{DpapiResult, Error, ErrorKind};
