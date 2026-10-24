use clap::{Args, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "fkw",
    version,
    about = "Seal secrets and files",
    disable_help_subcommand = true
)]
pub struct Cli {
    /// Recovery file for unlocking, or for a new recovery method.
    #[arg(short = 'r', long, global = true, value_name = "FILE")]
    pub recovery_file: Option<PathBuf>,
    /// Never ask for terminal input; require explicit choices.
    #[arg(long, global = true)]
    pub no_input: bool,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Seal a file, piped stdin, or hidden text.
    Seal(Seal),
    /// Open verified plaintext to a new file or stdout.
    Open {
        #[arg(default_value = "-", value_name = "FILE")]
        input: PathBuf,
        #[command(flatten)]
        output: Output,
        #[command(flatten)]
        unlock: Unlock,
    },
    /// List public, unverified unlock methods.
    Info {
        #[arg(default_value = "-", value_name = "FILE")]
        input: PathBuf,
    },
    /// Unlock and verify a complete file without releasing plaintext.
    Verify {
        #[arg(default_value = "-", value_name = "FILE")]
        input: PathBuf,
        #[command(flatten)]
        unlock: Unlock,
    },
    /// Add, replace, or remove an alternative unlock method.
    Access {
        #[command(subcommand)]
        command: Access,
    },
    /// Generate a private recovery file; keep it separate from sealed data.
    Recovery {
        #[arg(value_name = "FILE")]
        output: PathBuf,
    },
}

#[derive(Args)]
pub struct Seal {
    /// Plaintext file; omit or use - for stdin.
    #[arg(value_name = "FILE")]
    pub input: Option<PathBuf>,
    /// Enter short text through a hidden prompt (takes no argument).
    #[arg(short = 't', long, conflicts_with = "input")]
    pub text: bool,
    #[command(flatten)]
    pub output: Output,
    /// Write printable encrypted text (also accepted by open, info and verify).
    #[arg(long)]
    pub armor: bool,
    #[command(flatten)]
    pub enroll: Enroll,
    /// Reuse an enrollment snapshot retained after a failed save.
    #[arg(long, value_name = "ENVELOPE", conflicts_with_all = ["with", "name", "uv", "managed", "store_access"])]
    pub resume: Option<PathBuf>,
    /// Select a method when resuming an enrollment snapshot.
    #[arg(short = 'u', long, requires = "resume", value_name = "METHOD")]
    pub using: Option<String>,
}

#[derive(Args)]
pub struct Output {
    /// New destination; - means stdout.
    #[arg(short = 'o', long, conflicts_with = "stdout", value_name = "FILE")]
    pub output: Option<PathBuf>,
    /// Write data to stdout.
    #[arg(short = 'c', long)]
    pub stdout: bool,
}

#[derive(Args)]
pub struct Unlock {
    /// Unlock using an exact label or unique ID prefix.
    #[arg(short = 'u', long, value_name = "METHOD")]
    pub using: Option<String>,
}

#[derive(Args)]
pub struct Enroll {
    /// Protection recipe; ask interactively when omitted.
    #[arg(short = 'w', long, value_enum, value_name = "RECIPE")]
    pub with: Option<Recipe>,
    /// Public label for the new method.
    #[arg(short = 'n', long)]
    pub name: Option<String>,
    /// Require security-key user verification instead of touch alone.
    #[arg(long)]
    pub uv: bool,
    /// Use a discoverable credential that supports individual retirement.
    #[arg(long)]
    pub managed: bool,
    /// Exact OS keystore access policy.
    #[arg(long, value_enum)]
    pub store_access: Option<StoreAccess>,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum Recipe {
    Key,
    Passphrase,
    #[value(name = "key+passphrase")]
    KeyPassphrase,
    Keystore,
    #[value(name = "key+keystore")]
    KeyKeystore,
    Recovery,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum StoreAccess {
    Standard,
    UserAuthentication,
    MacosLogin,
}

#[derive(Args)]
pub struct Edit {
    /// Sealed file, or - for stdin.
    #[arg(value_name = "FILE")]
    pub input: PathBuf,
    /// New destination; the original is preserved.
    #[arg(short = 'o', long, value_name = "FILE")]
    pub output: PathBuf,
    #[command(flatten)]
    pub unlock: Unlock,
}

#[derive(Args)]
pub struct NewMethod {
    #[command(flatten)]
    pub enroll: Enroll,
    /// Recovery file for the new method, separate from the unlocking file.
    #[arg(long, value_name = "FILE")]
    pub new_recovery_file: Option<PathBuf>,
}

#[derive(Subcommand)]
pub enum Access {
    /// Add another way to unlock the file.
    Add {
        #[command(flatten)]
        edit: Edit,
        #[command(flatten)]
        new: NewMethod,
    },
    /// Enroll a new method in place of METHOD; external factors remain intact.
    Replace {
        #[command(flatten)]
        edit: Edit,
        /// Existing label or unique ID prefix; ask when omitted.
        method: Option<String>,
        #[command(flatten)]
        new: NewMethod,
    },
    /// Remove METHOD from this copy; external factors remain intact.
    Remove {
        #[command(flatten)]
        edit: Edit,
        /// Existing label or unique ID prefix; ask when omitted.
        method: Option<String>,
    },
    /// Finish a failed access update using its retained enrollment snapshot.
    Restore {
        #[command(flatten)]
        edit: Edit,
        #[arg(long, value_name = "FILE")]
        envelope: PathBuf,
    },
}
