extern crate ukhasnet_parser;
extern crate rustc_serialize;
extern crate hyper;
extern crate time;

use std::str;
use std::string::String;
use std::io::prelude::*;
use std::io::BufReader;
use std::net::TcpStream;

use rustc_serialize::json;
use ukhasnet_parser::{parse, DataField, Packet, Done, Error, Incomplete};
use hyper::client::Client;

#[derive(Debug,RustcDecodable)]
struct SocketMessage {
    i: u32,
    ni: u32,
    nn: String,
    p: String,
    r: i32,
    s: String,
    t: String
}

fn packet_to_influx(sm: &SocketMessage, p: &Packet) -> String {
    let node = p.path.iter().nth(0).unwrap();
    let mut line = String::from(
        format!("packet,gateway={},node={} ", sm.nn, node));

    line.push_str(&format!("gw_rssi={}i", sm.r));

    let mut temperature_count = 0;
    let mut voltage_count = 0;
    let mut humidity_count = 0;
    let mut pressure_count = 0;
    let mut sun_count = 0;
    let mut rssi_count = 0;
    let mut count_count = 0;
    let mut custom_count = 0;
    let mut location_count = 0;
    let mut windspeed_count = 0;
    let mut zombie_count = 0;
    let mut comment_count = 0;

    fn numeric_field(name: &str, d: &Vec<f32>, c: i32, field: &mut String) {
        let mut cc = 0;
        for f in d {
            cc += 1;
            field.push_str(&format!(",{}_{}_{}={}", name, c, cc, f));
        }
    }

    for df in &p.data {
        match df {
            &DataField::Temperature(ref t) => {
                temperature_count += 1;
                numeric_field("temperature", t, temperature_count, &mut line);
            },
            &DataField::Voltage(ref v) => {
                voltage_count += 1;
                numeric_field("voltage", &v, voltage_count, &mut line);
            },
            &DataField::Humidity(ref h) => {
                humidity_count += 1;
                numeric_field("humidity", &h, humidity_count, &mut line);
            },
            &DataField::Pressure(ref p) => {
                pressure_count += 1;
                numeric_field("pressure", &p, pressure_count, &mut line);
            },
            &DataField::Sun(ref s) => {
                sun_count += 1;
                numeric_field("sun", &s, sun_count, &mut line);
            },
            &DataField::Rssi(ref r) => {
                rssi_count += 1;
                numeric_field("rssi", &r, rssi_count, &mut line);
            },
            &DataField::Count(ref c) => {
                count_count += 1;
                numeric_field("count", &c, count_count, &mut line);
            },
            &DataField::Custom(ref c) => {
                custom_count += 1;
                numeric_field("custom", &c, custom_count, &mut line);
            },
            &DataField::Location(ref l) => {
                location_count += 1;
                line.push_str(&format!(",location_{}_latitude={}",
                                      location_count, l.latitude));
                line.push_str(&format!(",location_{}_longitude={}",
                                      location_count, l.longitude));
                match l.altitude {
                    Some(a) => line.push_str(
                        &format!(",location_{}_altitude={}",
                                location_count, a)),
                    None => ()
                }
            },
            &DataField::WindSpeed(ref w) => {
                windspeed_count += 1;
                line.push_str(&format!(",windspeed_{}_speed={}",
                                      windspeed_count, w.speed));
                match w.bearing {
                    Some(b) => line.push_str(
                        &format!(",windspeeed_{}_bearing={}",
                                windspeed_count, b)),
                    None => ()
                }
            },
            &DataField::Zombie(ref z) => {
                zombie_count += 1;
                line.push_str(&format!(",zombie_{}={}i", zombie_count, z));
            },
            &DataField::Comment(ref c) => {
                comment_count += 1;
                line.push_str(&format!(",comment_{}=\"{}\"", comment_count, c));
            }
        }
    }

    let ts = time::strptime(&sm.t, "%Y-%m-%dT%H:%M:%S.%fZ").unwrap();
    let ts = ts.to_timespec();
    let ts = (ts.sec as u64) * 1000000000 + ts.nsec as u64;
    line.push_str(&format!(" {}", ts));
    line
}

fn post_influx(line: &String) {
    let client = Client::new();
    client.post("http://localhost:8086/write?db=ukhasnet")
          .body(line).send().unwrap();
}

fn main() {
    let stream = TcpStream::connect("ukhas.net:3010").unwrap();
    let mut bufstream = BufReader::new(stream);
    loop {
        let mut data = Vec::new();
        match bufstream.read_until(b'}', &mut data) {
            Ok(_) => (),
            Err(e) => {
                println!("Error reading from socket: {}", e);
                break
            }
        }

        let jsonstr = match str::from_utf8(&data) {
            Ok(s) => s,
            Err(e) => {
                println!("Error converting data to string: {}", e);
                continue;
            }
        };

        let message = match json::decode::<SocketMessage>(&jsonstr) {
            Ok(m) => m,
            Err(e) => {
                println!("Error parsing message JSON: {}", e);
                continue;
            }
        };

        println!("[{}] ({}) {}:", message.t, message.r, message.nn);

        let packet = match parse(&message.p) {
            Done(_, p) => p,
            Error(e) => {println!("Error parsing packet: {}", e); continue;},
            Incomplete(_) => {println!("Packet data incomplete"); continue;}
        };

        let line = packet_to_influx(&message, &packet);
        post_influx(&line);
        println!("{}\n", line);
    }
}
