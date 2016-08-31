extern crate ukhasnet_parser;
extern crate rustc_serialize;
extern crate hyper;
extern crate time;
extern crate toml;

use std::str;
use std::string::String;
use std::io::prelude::*;
use std::fs::File;
use std::io::BufReader;
use std::net::TcpStream;
use std::env::args;
use std::time::Duration;
use std::thread::sleep;
use rustc_serialize::Decodable;

use rustc_serialize::json;
use ukhasnet_parser::{parse, DataField, Packet, Done, Error, Incomplete};
use hyper::client::Client;
use hyper::header::{Headers, Authorization, Basic};

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

#[derive(Debug,RustcDecodable)]
struct Config {
    ukhasnet: UkhasnetConfig,
    influxdb: InfluxDBConfig,
}

#[derive(Debug,RustcDecodable)]
struct UkhasnetConfig {
    socket: String,
}

#[derive(Debug,RustcDecodable)]
struct InfluxDBConfig {
    url: String,
    username: String,
    password: String,
}

fn read_config() -> Config {
    let path = match args().nth(1) {
        Some(s) => s,
        None => panic!("Please specify path to config file.")
    };

    let mut f = match File::open(&path) {
        Ok(f) => f,
        Err(e) => panic!("Error opening config file '{}': {}", &path, e)
    };

    let mut s = String::new();
    match f.read_to_string(&mut s) {
        Ok(_) => (),
        Err(e) => panic!("Error reading config file '{}': {}", &path, e)
    };

    let v = match toml::Parser::new(&s).parse() {
        Some(v) => toml::Value::Table(v),
        None => panic!("Error parsing config file '{}'", &path)
    };

    let mut decoder = toml::Decoder::new(v);
    match Config::decode(&mut decoder) {
        Ok(c) => c,
        Err(e) => panic!("Error parsing config file '{}': {}", &path, e)
    }
}

fn packet_to_influx(sm: &SocketMessage, p: &Packet) -> Result<String, String> {
    let node = match p.path.iter().nth(0) {
        Some(s) => s,
        None => { return Err("No origin node name in path".to_owned()) }
    };
    let pathend = match p.path.last() {
        Some(s) => s,
        None => { return Err("No node at end of path".to_owned()) }
    };
    let mut line = String::from(
        format!("packet,gateway={},node={},pathend={} gw_rssi={}i",
                sm.nn, node, pathend, sm.r));

    let mut temperature_count = 0;
    let mut voltage_count = 0;
    let mut current_count = 0;
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
            &DataField::Current(ref i) => {
                current_count += 1;
                numeric_field("current", &i, current_count, &mut line);
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

    let ts = match time::strptime(&sm.t, "%Y-%m-%dT%H:%M:%S.%fZ") {
        Ok(ts) => ts,
        Err(e) => { return Err(format!("Cannot parse timestamp: {}", e)) }
    }.to_timespec();
    let ts = (ts.sec as u64) * 1000000000 + ts.nsec as u64;
    line.push_str(&format!(" {}", ts));

    Ok(line)
}

fn post_influx(line: &String, config: &InfluxDBConfig) -> Result<(), String> {
    let client = Client::new();
    let mut headers = Headers::new();
    headers.set(
        Authorization(
            Basic {
                username: config.username.to_owned(),
                password: Some(config.password.to_owned()),
            }
        )
    );
    match client.post(&config.url).body(line).headers(headers).send() {
        Ok(_) => Ok(()),
        Err(e) => Err(format!("Error posting to InfluxDB: {}", e))
    }
}

fn update_packets_per_min(counter: &mut u32, minute: &mut i32,
                          config: &InfluxDBConfig) {
    let tm = time::now();
    *counter += 1;
    if tm.tm_min != *minute {
        if *minute != -1 {
            println!("Measured {} packets per minute", counter);
            let line = format!("packets_per_minute rate={}i", counter);
            let _ = post_influx(&line, config);
        }
        *minute = tm.tm_min;
        *counter = 1;
    }
}

fn main() {
    // Read config file. Panic and fail out if we cannot read it.
    let config = read_config();

    // Store packets processed per minute
    let mut rate: u32 = 0;
    let mut minute: i32 = -1;

    // Keep retrying the connect-process cycle.
    loop {

        // Connect to TCP socket
        println!("Connecting to TCP socket '{}'", config.ukhasnet.socket);
        let socket_addr: &str = &config.ukhasnet.socket;
        let stream = match TcpStream::connect(&socket_addr) {
            Ok(s) => s,
            Err(e) => {
                println!("Error connecting to socket: {}", e);
                println!("Retrying in ten seconds...");
                sleep(Duration::from_secs(10));
                continue
            }
        };
        match stream.set_read_timeout(Some(Duration::from_secs(10))) {
            Ok(_) => (),
            Err(e) => {
                println!("Error setting socket timeout: {}", e);
                println!("Retrying socket in ten seconds...");
                sleep(Duration::from_secs(10));
                continue
            }
        };
        let mut bufstream = BufReader::new(stream);

        // While connected, keep reading packets and processing them
        loop {
            let mut data = Vec::new();

            // If we error reading from the socket, break and retry above
            match bufstream.read_until(b'}', &mut data) {
                Ok(_) => (),
                Err(e) => {
                    println!("Error reading from socket: {}", e);
                    break
                }
            }

            // Errors in parsing the data into a sentence might indicate a
            // faulty link, so break and reconnect.
            let jsonstr = match str::from_utf8(&data) {
                Ok(s) => s,
                Err(e) => {
                    println!("Error converting data to string: {}", e);
                    break;
                }
            };
            let message = match json::decode::<SocketMessage>(&jsonstr) {
                Ok(m) => m,
                Err(e) => {
                    println!("Error parsing message JSON: {}", e);
                    break;
                }
            };
            println!("[{}] ({}) {}: {}",
                     message.t, message.r, message.nn, message.p);

            // Parse the message into a packet
            let packet = match parse(&message.p) {
                Done(_, p) => p,
                Error(e) => {println!("Error parsing packet: {}", e); continue;},
                Incomplete(_) => {println!("Packet data incomplete"); continue;}
            };

            // Upload the packet to InfluxDB
            let line = match packet_to_influx(&message, &packet) {
                Ok(l) => l,
                Err(e) => {
                    println!("Error converting packet to Influx: {}", e);
                    continue
                }
            };
            match post_influx(&line, &config.influxdb) {
                Ok(_) => (),
                Err(e) => {
                    println!("Error posting to InfluxDB: {}", e);
                    continue
                }
            };

            // Update how many packets we've been processing
            update_packets_per_min(&mut rate, &mut minute, &config.influxdb);
        }
    }
}
