mod models;
mod crypto;
mod database;
mod cli;

#[cfg(test)]
mod tests;

use anyhow::Result;

fn main() -> Result<()> {
    // Set up error handling
    std::panic::set_hook(Box::new(|panic_info| {
        eprintln!("Fatal error: {}", panic_info);
        std::process::exit(1);
    }));

    // Run the CLI handler
    cli::CliHandler::run()
}
