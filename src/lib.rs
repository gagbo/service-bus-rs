#![deny(rust_2018_idioms)]
use crypto;
use hyper;
#[macro_use]
use lazy_static;
use rustc_serialize as serialize;
use serde;
use serde_derive;
use serde_json;
use ::time as time2;
use url;

/// Contains shared functionality between all the different
/// modules inside of the Azure Libary
///
pub mod core;

/// The Service Bus module provides a wrapper around the Azure Service Bus
/// REST Api's. This includes the Service Queue and Topics.
/// They communicate messages through the BrokeredMessage struct.
///
pub mod servicebus;
