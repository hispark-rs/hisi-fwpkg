//! `hisi-fwpkg` CLI — pack a compiled program into a HiSilicon app image and/or
//! fwpkg firmware package.

use {
    clap::{Parser, Subcommand, ValueEnum},
    hisi_fwpkg::{
        pack_app_fwpkg, patch_hash, plan_app_flash, Chip, ImagePlanOptions, PackOptions,
        PartitionType, IMAGE_HEADER_LEN,
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
        /// Target chip (sets the app partition flash address in the plan).
        #[arg(short, long, value_enum, default_value = "ws63")]
        chip: ChipArg,
        /// Override the app partition burn address (hex ok, e.g. 0x230000).
        #[arg(long, value_parser = parse_u32)]
        app_addr: Option<u32>,
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
    /// Patch the body SHA-256 into an already-headered image's `code_area_hash`.
    ///
    /// Makes a link-time `boot-header` ELF (or a raw headered bin) bootable:
    /// computes the SHA-256 of the body and writes it into `code_area_hash`
    /// (flashboot checks the body hash even with secure-verify disabled). The
    /// header's `code_area_len` selects how many body bytes are hashed; if it is
    /// zero, the whole body is hashed and the length fields are filled too.
    /// Patches in place unless `-o` is given.
    PatchHash {
        /// Input ELF (with a `.boot_header` section) or raw headered bin.
        input: PathBuf,
        /// Output path (defaults to overwriting `input` in place).
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Print the canonical flash plan and optionally write the planned image.
    Plan {
        /// Input ELF, raw body .bin, already-headered image, or fwpkg.
        input: PathBuf,
        /// Target chip (sets the app partition flash address).
        #[arg(short, long, value_enum, default_value = "ws63")]
        chip: ChipArg,
        /// Override the app partition burn address (hex ok, e.g. 0x230000).
        #[arg(long, value_parser = parse_u32)]
        app_addr: Option<u32>,
        /// Write the planned complete image to this path.
        #[arg(long)]
        image_output: Option<PathBuf>,
        /// Output format.
        #[arg(long, value_enum, default_value = "json")]
        format: PlanFormat,
    },
}

#[derive(Copy, Clone, ValueEnum)]
enum PlanFormat {
    Json,
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
        Command::Image {
            input,
            output,
            chip,
            app_addr,
        } => {
            let bytes = std::fs::read(&input)?;
            let chip: Chip = chip.into();
            let opts = ImagePlanOptions {
                pack: PackOptions {
                    app_addr,
                    ..Default::default()
                },
            };
            let plan = plan_app_flash(&bytes, chip, &opts)?;
            std::fs::write(&output, &plan.image_bytes)?;
            eprintln!(
                "wrote {} ({} bytes: {} header + {} body) @ 0x{:08X}",
                output.display(),
                plan.image_len,
                IMAGE_HEADER_LEN,
                plan.image_len as usize - IMAGE_HEADER_LEN,
                plan.base_addr
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
        Command::PatchHash { input, output } => {
            let bytes = std::fs::read(&input)?;
            let patched = patch_hash(&bytes)?;
            let out = output.unwrap_or_else(|| input.clone());
            std::fs::write(&out, &patched)?;
            // Echo the patched hash (code_info+0x28) for verification.
            let hash = hisi_fwpkg::patched_hash(&patched).unwrap_or([0u8; 32]);
            let hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();
            eprintln!("patched {} — code_area_hash = {hex}", out.display());
        }
        Command::Plan {
            input,
            chip,
            app_addr,
            image_output,
            format,
        } => {
            let bytes = std::fs::read(&input)?;
            let chip: Chip = chip.into();
            let opts = ImagePlanOptions {
                pack: PackOptions {
                    app_addr,
                    ..Default::default()
                },
            };
            let plan = plan_app_flash(&bytes, chip, &opts)?;
            if let Some(path) = image_output {
                std::fs::write(&path, &plan.image_bytes)?;
                eprintln!("wrote planned image {}", path.display());
            }
            match format {
                PlanFormat::Json => {
                    println!("{}", serde_json::to_string_pretty(&plan).unwrap());
                }
            }
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
