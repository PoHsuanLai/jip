# vhs tape: jip demo
# Render with: vhs docs/demo.tape
# Requires: `cargo install --path jip-cli` first (puts `jip` on PATH).

Output docs/demo.gif

Set Shell "bash"
Set FontSize 14
Set Width 1200
Set Height 660
Set PlaybackSpeed 1.0
Set TypingSpeed 40ms
Set Theme "Catppuccin Mocha"

Env CLICOLOR_FORCE "1"

Sleep 1s

Type "jip"
Sleep 300ms
Enter
Sleep 2500ms

Type "jip who"
Sleep 300ms
Enter
Sleep 3500ms

Type "jip reach cloudflare.com"
Sleep 300ms
Enter
Sleep 4000ms
