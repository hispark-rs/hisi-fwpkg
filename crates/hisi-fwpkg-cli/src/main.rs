//! `hisi-fwpkg` CLI — pack a compiled program into a HiSilicon app image and/or
//! fwpkg firmware package.

use {
    clap::{Parser, Subcommand, ValueEnum},
    hisi_fwpkg::{
        build_app_image_from_input, pack_app_fwpkg, Chip, PackOptions, PartitionType,
        IMAGE_HEADER_LEN,
    },
    std::{path::PathBuf, process::ExitCode},
};

/// Pack HiSilicon WS63/BS2X application images and fwpkg packages.
#[derive(Parser)]
#[command(name = "hisi-fwpkg", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Copy, Clone, ValueEnum)]
enum ChipArg {
    Ws63,
    Bs21,
}

impl From<ChipArg> for Chip {
    fn from(c: ChipArg) -> Self {
        match c {
            ChipArg::Ws63 => Chip::Ws63,
            ChipArg::Bs21 => Chip::Bs21,
        }
    }
}

#[derive(Subcommand)]
enum Command {
    /// ELF/bin -> app image (0x300 header || body). Writes the raw image.
    Image {
        /// Input ELF or raw .bin.
        input: PathBuf,
        /// Output image path.
        #[arg(short, long)]
        output: PathBuf,
    },
    /// ELF/bin -> app image -> single-partition fwpkg (app only).
    Pack {
        /// Input ELF or raw .bin.
        input: PathBuf,
        /// Output .fwpkg path.
        #[arg(short, long)]
        output: PathBuf,
        /// Target chip (sets the app partition flash address).
        #[arg(short, long, value_enum, default_value = "ws63")]
        chip: ChipArg,
        /// Override the app partition burn address (hex ok, e.g. 0x230000).
        #[arg(long, value_parser = parse_u32)]
        app_addr: Option<u32>,
        /// Partition name inside the fwpkg.
        #[arg(long, default_value = "app")]
        name: String,
    },
}

fn parse_u32(s: &str) -> Result<u32, String> {
    let s = s.trim();
    let v = if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16)
    } else {
        s.parse()
    };
    v.map_err(|e| format!("invalid number {s:?}: {e}"))
}

fn run() -> hisi_fwpkg::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Image { input, output } => {
            let bytes = std::fs::read(&input)?;
            let opts = PackOptions::default();
            let image = build_app_image_from_input(&bytes, &opts)?;
            std::fs::write(&output, &image)?;
            eprintln!(
                "wrote {} ({} bytes: {} header + {} body)",
                output.display(),
                image.len(),
                IMAGE_HEADER_LEN,
                image.len() - IMAGE_HEADER_LEN
            );
        }
        Command::Pack {
            input,
            output,
            chip,
            app_addr,
            name,
        } => {
            let bytes = std::fs::read(&input)?;
            let chip: Chip = chip.into();
            let opts = PackOptions {
                app_addr,
                app_name: Some(name.clone()),
                ..Default::default()
            };
            let pkg = pack_app_fwpkg(&bytes, chip, &opts)?;
            std::fs::write(&output, &pkg)?;
            let addr = app_addr.unwrap_or_else(|| chip.app_partition_addr());
            eprintln!(
                "wrote {} ({} bytes) — partition {:?} '{}' @ 0x{:08X}",
                output.display(),
                pkg.len(),
                PartitionType::Normal,
                name,
                addr
            );
        }
    }
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
