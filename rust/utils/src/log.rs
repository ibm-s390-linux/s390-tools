// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2023

use log::{self, Level, LevelFilter, Log, Metadata, Record};

/// A simple Logger that prints to stderr if the verbosity level is high enough.
/// Prints log-level for Debug+Trace
#[derive(Clone, Default, Debug)]
pub struct PvLogger;

impl PvLogger {
    /// Set self as the logger for this application.
    ///
    /// # Errors
    ///
    /// An error is returned if a logger has already been set.
    pub fn start(&'static self, filter: LevelFilter) -> Result<(), log::SetLoggerError> {
        log::set_logger(self).map(|()| log::set_max_level(filter))
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
