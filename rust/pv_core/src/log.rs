// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2023

use log::{self, Level, LevelFilter, Log, Metadata, Record};

/// A simple Logger that prints to stderr if the verbosity level is high enough.
/// Prints log-level for Debug+Trace
#[derive(Clone, Default, Debug)]
pub struct PvLogger;

fn to_level(verbosity: u8) -> LevelFilter {
    match verbosity {
        // Error and Warn on by default
        0 => LevelFilter::Warn,
        1 => LevelFilter::Info,
        2 => LevelFilter::Debug,
        _ => LevelFilter::Trace,
    }
}

impl PvLogger {
    /// Set self as the logger for this application.
    ///
    /// # Errors
    ///
    /// An error is returned if a logger has already been set.
    pub fn start(&'static self, verbosity: u8) -> Result<(), log::SetLoggerError> {
        log::set_logger(self).map(|()| log::set_max_level(to_level(verbosity)))
    }
}

impl Log for PvLogger {
    fn enabled(&self, _metadata: &Metadata) -> bool {
        true
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            if record.level() > Level::Info {
                eprintln!("{}: {}", record.level(), record.args());
            } else {
                eprintln!("{}", record.args());
            }
        }
    }
    fn flush(&self) {}
}
