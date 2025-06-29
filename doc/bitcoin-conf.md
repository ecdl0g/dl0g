# `bitcoin.conf` Configuration File

The configuration file is used by `bitcoind`, `bitcoin-qt` and `bitcoin-cli`.

All command-line options (except for `-?`, `-help`, `-version` and `-conf`) may be specified in a configuration file, and all configuration file options (except for `includeconf`) may also be specified on the command line. Command-line options override values set in the configuration file and configuration file options override values set in the GUI.

Changes to the configuration file while `bitcoind` or `bitcoin-qt` is running only take effect after restarting.

Users should never make any configuration changes which they do not understand. Furthermore, users should always be wary of accepting any configuration changes provided to them by another source (even if they believe that they do understand them).

## Configuration File Precedence

Options specified in the configuration file can be overridden by options in the [`settings.json` file](files.md) and by options specified on the command line.

The `settings.json` file contains dynamic settings that are set by the Bitcoin Core GUI and RPCs at runtime, and augment or replace the static settings specified in the `bitcoin.conf` file.

Command line options also augment or replace `bitcoin.conf` options, and can be useful for scripting and debugging.

It is possible to see which setting values are in use by checking `debug.log` output. Any unrecognized options that are found in `bitcoin.conf` also show up as warnings in `debug.log` output.

## Configuration File Format

The configuration file is a plain text file and consists of `option=value` entries, one per line. Leading and trailing whitespaces are removed.

In contrast to the command-line usage:
- an option must be specified without leading `-`;
- a value of the given option is mandatory; e.g., `testnet=1` (for chain selection options), `noconnect=1` (for negated options).

### Blank lines

Blank lines are allowed and ignored by the parser.

### Comments

A comment starts with a number sign (`#`) and extends to the end of the line. All comments are ignored by the parser.

Comments may appear in two ways:
- on their own on an otherwise empty line (_preferable_);
- after an `option=value` entry.

### Network specific options

Network specific options can be:
- placed into sections with headers `[main]` (not `[mainnet]`), `[test]` (not `[testnet]`, for testnet3), `[testnet4]`, `[signet]` or `[regtest]`;
- prefixed with a chain name; e.g., `regtest.maxmempool=100`.

Network specific options take precedence over non-network specific options.
If multiple values for the same option are found with the same precedence, the
first one is generally chosen.

This means that given the following configuration, `regtest.rpcport` is set to `3000`:

```
regtest=1
rpcport=2000
regtest.rpcport=3000

[regtest]
rpcport=4000
```

### Negated options

Almost all options can be negated by being specified with a `no` prefix. For example an option `-foo` could be negated by writing `nofoo=1` or `nofoo=` in the configuration file or `-nofoo=1` or `-nofoo` on the command line.

In general, negating an option is like setting it to `0` if it is a boolean or integer option, and setting it to an empty string or path or list if it is a string or path or list option.

However, there are exceptions to this general rule. For example, it is an error to negate some options (e.g. `-nodatadir` is disallowed), and some negated strings are treated like `"0"` instead of `""` (e.g. `-noproxy` is treated like `-proxy=0`), and some negating some lists can have side effects in addition to clearing the lists (e.g. `-noconnect` disables automatic connections in addition to dropping any manual connections specified previously with `-connect=<host>`). When there are exceptions to the rule, they should either be obvious from context, or should be mentioned in usage documentation. Nonobvious, undocumented exceptions should be reported as bugs.

## Configuration File Path

The configuration file is not automatically created; you can create it using your favorite text editor. By default, the configuration file name is `bitcoin.conf` and it is located in the Bitcoin data directory, but both the Bitcoin data directory and the configuration file path may be changed using the `-datadir` and `-conf` command-line options.

The `includeconf=<file>` option in the `bitcoin.conf` file can be used to include additional configuration files.

### Default configuration file locations

Operating System | Data Directory | Example Path
-- | -- | --
Windows | `%LOCALAPPDATA%\Bitcoin\` | `C:\Users\username\AppData\Local\Bitcoin\bitcoin.conf`
Linux | `$HOME/.dlog/` | `/home/username/.dlog/bitcoin.conf`
macOS | `$HOME/Library/Application Support/Bitcoin/` | `/Users/username/Library/Application Support/Bitcoin/bitcoin.conf`

An example configuration file can be generated by [contrib/devtools/gen-bitcoin-conf.sh](../contrib/devtools/gen-bitcoin-conf.sh).
Run this script after compiling to generate an up-to-date configuration file.
The output is placed under `share/examples/bitcoin.conf`.
To use the generated configuration file, copy the example file into your data directory and edit it there, like so:

```
# example copy command for linux user
cp share/examples/bitcoin.conf ~/.dlog
```
