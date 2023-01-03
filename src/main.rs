#[macro_use]
extern crate log;
extern crate fern;
extern crate ukhasnet_parser;
extern crate rustc_serialize;
extern crate reqwest;
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
use reqwest::blocking::Client;
use ukhasnet_parser::{parse, Packet, DataField};

#[derive(Debug,RustcDecodable)]
struct SocketMessage {
    nn: String,
    p: String,
    r: i32,
    t: String,
    a: i32,
}

#[derive(Debug,RustcDecodable)]
struct Config {
    ukhasnet: UkhasnetConfig,
    influxdb: InfluxDBConfig,
    logfile: String
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
        format!("packet,gateway={},node={},pathend={} gw_rssi={}i,gw_age={}i",
                sm.nn, node, pathend, sm.r, sm.a));

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
                match l.latlng {
                    Some((latitude, longitude)) => {
                        line.push_str(&format!(",location_{}_latitude={}",
                                              location_count, latitude));
                        line.push_str(&format!(",location_{}_longitude={}",
                                              location_count, longitude));
                    },
                    None => ()
                }
                match l.alt {
                    Some(alt) => line.push_str(
                        &format!(",location_{}_altitude={}",
                                location_count, alt)),
                    None => ()
                }
            },
            &DataField::WindSpeed(ref w) => {
                windspeed_count += 1;
                match w.speed {
                    Some(speed) => {
                        line.push_str(&format!(",windspeed_{}_speed={}",
                                              windspeed_count, speed));
                    },
                    None => ()
                }
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
        }
    }

    match p.comment {
        Some(ref comment) => {
            line.push_str(&format!(",message=\"{}\"", comment))
        },
        None => (),
    }

    line.push_str(&format!(",sentence=\"{}\"", sm.p));

    let ts = match time::strptime(&sm.t, "%Y-%m-%dT%H:%M:%S.%fZ") {
        Ok(ts) => ts,
        Err(e) => { return Err(format!("Cannot parse timestamp: {}", e)) }
    }.to_timespec();
    let ts = (ts.sec as u64) * 1000000000 + ts.nsec as u64;
    line.push_str(&format!(" {}", ts));

    Ok(line)
}

fn post_influx(client: &Client, line: &str, config: &InfluxDBConfig)
        -> Result<(), String> {
    match client.post(&config.url)
                .body(line.to_owned())
                .basic_auth(&config.username, Some(&config.password))
                .send() {
        Ok(resp) => match resp.bytes() {
            Ok(_) => Ok(()),
            Err(e) => Err(format!("Error posting to InfluxDB: {}", e)),
        },
        Err(e) => Err(format!("Error posting to InfluxDB: {}", e))
    }
}

fn update_packets_per_min(client: &Client, counter: &mut u32, minute: &mut i32,
                          config: &InfluxDBConfig) {
    let tm = time::now();
    *counter += 1;
    if tm.tm_min != *minute {
        if *minute != -1 {
            println!("Measured {} packets per minute", counter);
            let line = format!("packets_per_minute rate={}i", counter);
            let _ = post_influx(client, &line, config);
        }
        *minute = tm.tm_min;
        *counter = 1;
    }
}

fn main() {
    // Read config file. Panic and fail out if we cannot read it.
    let config = read_config();

    // Set up logging
    let logger_config = fern::DispatchConfig {
        format: Box::new(|msg: &str, lvl: &log::LogLevel, _: &log::LogLocation| {
            format!("[{}] [{}] {}",
                    time::now_utc().strftime("%Y-%m-%dT%H:%M:%SZ").unwrap(),
                    lvl, msg)
        }),
        output: vec![fern::OutputConfig::stdout(),
                     fern::OutputConfig::file(&config.logfile)],
        level: log::LogLevelFilter::Info,
    };
    fern::init_global_logger(logger_config, log::LogLevelFilter::Info).unwrap();

    // Store packets processed per minute
    let mut rate: u32 = 0;
    let mut minute: i32 = -1;

    // Keep retrying the connect-process cycle.
    loop {

        // Connect to TCP socket
        info!("Connecting to TCP socket '{}'", config.ukhasnet.socket);
        let socket_addr: &str = &config.ukhasnet.socket;
        let stream = match TcpStream::connect(&socket_addr) {
            Ok(s) => s,
            Err(e) => {
                error!("Error connecting to socket: {}, retrying in 10s", e);
                sleep(Duration::from_secs(10));
                continue
            }
        };
        match stream.set_read_timeout(Some(Duration::from_secs(10))) {
            Ok(_) => (),
            Err(e) => {
                error!("Error setting socket timeout: {}, retrying in 10s", e);
                sleep(Duration::from_secs(10));
                continue
            }
        };
        let mut bufstream = BufReader::new(stream);

        // Make a client to pool connections to the InfluxDB server
        let client = Client::new();

        // While connected, keep reading packets and processing them
        loop {
            let mut data = String::new();

            // If we error reading from the socket, break and retry above
            match bufstream.read_line(&mut data) {
                Ok(_) => (),
                Err(e) => {
                    error!("Error reading from socket: {}", e);
                    break
                }
            }

            let message = match json::decode::<SocketMessage>(&data) {
                Ok(m) => m,
                Err(e) => {
                    error!("Error parsing message JSON: {}", e);
                    break;
                }
            };
            info!("Received packet [{}] RSSI={} AGE={} GW={} {}",
                     message.t, message.r, message.a, message.nn, message.p);

            // Parse the message into a packet
            let packet = match parse(&message.p) {
                Ok(p) => p,
                Err(e) => { error!("Parse error: {}", e); continue; },
            };

            // Upload the packet to InfluxDB
            let line = match packet_to_influx(&message, &packet) {
                Ok(l) => l,
                Err(e) => {
                    error!("Error converting packet to Influx: {}", e);
                    continue
                }
            };
            match post_influx(&client, &line, &config.influxdb) {
                Ok(_) => (),
                Err(e) => {
                    error!("Error posting to InfluxDB: {}", e);
                    continue
                }
            };

            // Update how many packets we've been processing
            update_packets_per_min(&client, &mut rate, &mut minute,
                                   &config.influxdb);
        }
    }
}
