use clap::{ArgGroup, Args, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "fkw",
    version,
    about = "Seal secrets and files",
    disable_help_subcommand = true,
    max_term_width = 100,
    after_help = "Examples:\n  fkw seal notes.txt -w key\n  fkw seal --text --armor -w passphrase\n  fkw open notes.txt.fkw -o restored.txt"
)]
pub struct Cli {
    /// Recovery file for unlocking or enrollment.
    #[arg(
        short = 'r',
        long,
        global = true,
        value_name = "FILE",
        display_order = 900
    )]
    pub recovery_file: Option<PathBuf>,
    /// Disable terminal input.
    #[arg(long, global = true, display_order = 901)]
    pub no_input: bool,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Seal a file, stdin, or hidden text.
    #[command(
        after_help = "Defaults: FILE.fkw for files; stdout with --armor and no input filename.\nKey enrollment requires a PIN; unlocking uses touch only unless --uv is set."
    )]
    Seal(Seal),
    /// Decrypt to a new file or stdout.
    #[command(
        group(ArgGroup::new("destination").args(["output", "stdout"]).required(true)),
        after_help = "The complete file is verified before any plaintext is written."
    )]
    Open {
        /// Sealed file; omit or use - for stdin.
        #[arg(default_value = "-", value_name = "FILE")]
        input: PathBuf,
        #[command(flatten)]
        output: Output,
        #[command(flatten)]
        unlock: Unlock,
    },
    /// Show unlock methods (unverified).
    Info {
        /// Sealed file; omit or use - for stdin.
        #[arg(default_value = "-", value_name = "FILE")]
        input: PathBuf,
    },
    /// Verify a sealed file without writing plaintext.
    Verify {
        /// Sealed file; omit or use - for stdin.
        #[arg(default_value = "-", value_name = "FILE")]
        input: PathBuf,
        #[command(flatten)]
        unlock: Unlock,
    },
    /// Manage a file's unlock methods.
    #[command(
        after_help = "Edits update the file after verification. Use -o to write a separate copy."
    )]
    Access {
        #[command(subcommand)]
        command: Access,
    },
    /// Create a recovery secret in a new file.
    #[command(after_help = "Keep the recovery file separate from your sealed data.")]
    Recovery {
        /// New recovery file.
        #[arg(value_name = "FILE")]
        output: PathBuf,
    },
}

#[derive(Args)]
pub struct Seal {
    /// Plaintext file; omit or use - for stdin.
    #[arg(value_name = "FILE")]
    pub input: Option<PathBuf>,
    /// Enter a single hidden line (takes no argument).
    #[arg(short = 't', long, conflicts_with_all = ["input", "no_input"])]
    pub text: bool,
    #[command(flatten)]
    pub output: Output,
    /// Write printable encrypted text.
    #[arg(long)]
    pub armor: bool,
    #[command(flatten)]
    pub enroll: Enroll,
    /// Retry a failed save using its enrollment snapshot.
    #[arg(long, value_name = "ENVELOPE", conflicts_with_all = ["with", "name", "uv", "managed", "store_access"])]
    pub resume: Option<PathBuf>,
    /// Select a method when resuming an enrollment snapshot.
    #[arg(short = 'u', long, requires = "resume", value_name = "METHOD")]
    pub using: Option<String>,
}

#[derive(Args)]
pub struct Output {
    /// Write a new file; - means stdout.
    #[arg(short = 'o', long, conflicts_with = "stdout", value_name = "FILE")]
    pub output: Option<PathBuf>,
    /// Write data to stdout.
    #[arg(short = 'c', long)]
    pub stdout: bool,
}

#[derive(Args)]
pub struct Unlock {
    /// Unlock by label or unique ID prefix (at least 4 characters).
    #[arg(short = 'u', long, value_name = "METHOD")]
    pub using: Option<String>,
}

#[derive(Args)]
pub struct Enroll {
    /// New unlock method; choose interactively if omitted.
    #[arg(short = 'w', long, value_enum, value_name = "RECIPE")]
    pub with: Option<Recipe>,
    /// Public label for the new method.
    #[arg(short = 'n', long, value_name = "LABEL")]
    pub name: Option<String>,
    /// Require PIN + touch when unlocking with a key.
    #[arg(long)]
    pub uv: bool,
    /// Create a discoverable key credential that can be retired.
    #[arg(long)]
    pub managed: bool,
    /// Keystore access policy (default: standard).
    #[arg(long, value_enum, value_name = "POLICY")]
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
    /// Write a separate new file instead of updating the input.
    #[arg(short = 'o', long, value_name = "FILE")]
    pub output: Option<PathBuf>,
    #[command(flatten)]
    pub unlock: Unlock,
}

#[derive(Args)]
pub struct NewMethod {
    #[command(flatten)]
    pub enroll: Enroll,
    /// Recovery file for the new method (defaults to -r).
    #[arg(long, value_name = "FILE")]
    pub new_recovery_file: Option<PathBuf>,
}

#[derive(Subcommand)]
pub enum Access {
    /// Add another way to unlock the file.
    #[command(
        after_help = "Unlocks with an existing method, then enrolls the new one.\nUpdates FILE unless -o is given. Key enrollment requires a PIN."
    )]
    Add {
        #[command(flatten)]
        edit: Edit,
        #[command(flatten)]
        new: NewMethod,
    },
    /// Replace an unlock method.
    #[command(
        after_help = "Unlocks with an existing method, then enrolls its replacement.\nUpdates FILE unless -o is given; keeps the old label unless -n is given.\nKey enrollment requires a PIN."
    )]
    Replace {
        #[command(flatten)]
        edit: Edit,
        /// Method to replace: label or unique ID prefix; choose if omitted.
        method: Option<String>,
        #[command(flatten)]
        new: NewMethod,
    },
    /// Remove an unlock method.
    #[command(
        after_help = "Updates FILE unless -o is given; unlock with a method you are keeping.\nOlder copies and external factors are unchanged."
    )]
    Remove {
        #[command(flatten)]
        edit: Edit,
        /// Method to remove: label or unique ID prefix; choose if omitted.
        method: Option<String>,
    },
    /// Retry a failed access edit using its enrollment snapshot.
    #[command(after_help = "Updates FILE unless -o is given.")]
    Restore {
        #[command(flatten)]
        edit: Edit,
        /// Enrollment snapshot retained after the failed save.
        #[arg(long, value_name = "FILE")]
        envelope: PathBuf,
    },
}
