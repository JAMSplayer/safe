use crate::error::{Error, Result};
use tracing::Level;
pub use ant_logging::ReloadHandle as LoggingHandle;

#[rustfmt::skip]
fn targets() -> Vec<(String, Level, Level, Level)> {
    vec![
//	    level:                        "trace",       "info",        "error"];
        ("ant_networking".to_string(), Level::DEBUG,  Level::ERROR,  Level::ERROR),
        ("safe".to_string(),           Level::TRACE,  Level::INFO,   Level::WARN),
        ("ant_build_info".to_string(), Level::TRACE,  Level::TRACE,  Level::TRACE),
        ("autonomi".to_string(),       Level::TRACE,  Level::TRACE,  Level::TRACE),
        ("ant_logging".to_string(),    Level::TRACE,  Level::INFO,   Level::WARN),
        ("ant_bootstrap".to_string(),  Level::TRACE,  Level::DEBUG,  Level::INFO),
        ("ant_protocol".to_string(),   Level::TRACE,  Level::DEBUG,  Level::INFO),
        ("ant_evm".to_string(),        Level::TRACE,  Level::DEBUG,  Level::INFO),
        ("evmlib".to_string(),         Level::TRACE,  Level::DEBUG,  Level::INFO),
    ]
}

pub fn init_logging(level: String, handle: Option<LoggingHandle>) -> Result<LoggingHandle> {
    let logging_targets = targets();

	let logging_targets = match level.as_str() {
		"trace" => Ok(logging_targets.iter().map(|target| ((*target).0.clone(), (*target).1)).collect::<Vec<(String, Level)>>()),
		"info" => Ok(logging_targets.iter().map(|target| ((*target).0.clone(), (*target).2)).collect::<Vec<(String, Level)>>()),
		"error" => Ok(logging_targets.iter().map(|target| ((*target).0.clone(), (*target).3)).collect::<Vec<(String, Level)>>()),
		_ => Err(Error::Custom(format!("Unknown logging target: {}", level))),
	}?;

	let reload_handle = if let Some(h) = handle {
		let targets: String = logging_targets.iter()
			.map(|target| format!("{}={}", target.0, target.1))
			.collect::<Vec<String>>()
			.join(",");
		h.modify_log_level(&targets).map_err(|e| Error::Custom(format!("Could not modify log levels: {}", e)))?;
		h
	} else {
	    let mut log_builder = ant_logging::LogBuilder::new(logging_targets);
	    log_builder.output_dest(ant_logging::LogOutputDest::Stdout);
	    log_builder.format(ant_logging::LogFormat::Default);
	    let (reload_handle, _) = log_builder
	        .initialize()
	        .map_err(|e| Error::Custom(format!("logging: {}", e)))?;
	    reload_handle
	};
    

    Ok(reload_handle)
}

