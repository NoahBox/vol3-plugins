# Volatility 3 Plugins

Small collection of plugins for Volatility 3.

## Included Plugins

| Plugin | Purpose |
| --- | --- |
| `windows.bitlocker.Bitlocker` | Recover BitLocker FVEKs, VMKs, and optional recovery key search. |
| `windows.ntqqkey.NTQQKey` | Extract NTQQ SQLCipher passphrases. |
| `windows.wechatkeys.WeChatKeys` | Extract WeChat SQLCipher raw keys. |
| `windows.veracrypt.VeraCrypt` | Extract VeraCrypt crypto material. |


## Usage

Clone this repository and point Volatility 3 at this repository with `-p` and run the plugin you want:

```bash
python vol.py -f memory.raw -p /path/to/vol3-plugins windows.bitlocker.Bitlocker
```


## Useful Options

| Plugin | Notable options |
| --- | --- |
| `Bitlocker` | `--pid`, `--scan-recovery-passwords`, `--export` |
| `NTQQKey` | `--pid`, `--db-dir`, `--include-unverified` |
| `WeChatKeys` | `--pid`, `--db-dir`, `--include-unverified` |
