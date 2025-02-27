use crate::error::{Error, Result};
use tracing::Level;
pub use ant_logging::ReloadHandle as LoggingHandle;

#[rustfmt::skip]
fn targets() -> Vec<(String, Option<Level>, Option<Level>, Option<Level>)> {
    vec![
//	    level:                                    "trace"              "info"               "error"];

        ("ant_networking".to_string(), Some(Level::DEBUG),  Some(Level::ERROR),              None ),
        ("safe".to_string(),           Some(Level::TRACE),  Some(Level::INFO),   Some(Level::WARN) ),
        ("ant_build_info".to_string(), Some(Level::TRACE),  Some(Level::TRACE),  Some(Level::WARN) ),
        ("autonomi".to_string(),       Some(Level::TRACE),  Some(Level::TRACE),  Some(Level::WARN) ),
        ("ant_logging".to_string(),    Some(Level::TRACE),  Some(Level::INFO),   Some(Level::WARN) ),
        ("ant_bootstrap".to_string(),  Some(Level::TRACE),  Some(Level::DEBUG),  Some(Level::WARN) ),
        ("ant_protocol".to_string(),   Some(Level::TRACE),  Some(Level::DEBUG),  Some(Level::WARN) ),
        ("ant_evm".to_string(),        Some(Level::TRACE),  Some(Level::DEBUG),  Some(Level::WARN) ),
        ("evmlib".to_string(),         Some(Level::TRACE),  Some(Level::DEBUG),  Some(Level::WARN) ),
    ]
}

pub fn logging(level: String, handle: Option<&LoggingHandle>) -> Result<Option<LoggingHandle>> {
    let logging_targets = targets();

	let logging_targets: Vec<(String, Option<Level>)> = match level.to_lowercase().as_str() {
		"trace" => Ok(logging_targets.iter().map(|target| ((*target).0.clone(), (*target).1)).collect()),
		"info"  => Ok(logging_targets.iter().map(|target| ((*target).0.clone(), (*target).2)).collect()),
		"error" => Ok(logging_targets.iter().map(|target| ((*target).0.clone(), (*target).3)).collect()),
		_ => Err(Error::Custom(format!("Unknown logging target: {}", level))),
	}?;

	let logging_targets: Vec<(String, Level)> = logging_targets.iter()
			.filter(|target| target.1.is_some())
			.map(|target| (target.0.clone(), target.1.unwrap()))
			.collect();

	if let Some(h) = handle {
		let targets: String = logging_targets.iter()
			.map(|target| format!("{}={}", target.0, target.1))
			.collect::<Vec<String>>()
			.join(",");
		h.modify_log_level(&targets).map_err(|e| Error::Custom(format!("Could not modify log levels: {}", e)))?;
		Ok(None)
	} else {
	    let mut log_builder = ant_logging::LogBuilder::new(logging_targets);
	    log_builder.output_dest(ant_logging::LogOutputDest::Stdout);
	    log_builder.format(ant_logging::LogFormat::Default);
	    let (reload_handle, _) = log_builder
	        .initialize()
	        .map_err(|e| Error::Custom(format!("logging: {}", e)))?;
	    Ok(Some(reload_handle))
	}
}

