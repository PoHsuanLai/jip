Output demo.gif

Set FontSize 14
Set Width 1000
Set Height 600
Set Theme "Dracula"
Set Shell "bash"
Set Padding 20
Set TypingSpeed 50ms
Set WindowBar Colorful

Hide
Type `PS1='\[\033[1;32m\]demo\[\033[0m\] $ '; clear`
Enter
Sleep 300ms
Show

# 1. Something feels slow — check the overview
Type "jip"
Enter
Sleep 2000ms

# 2. Diagnose: find the root cause
Type "jip check"
Enter
Sleep 2500ms

# 3. Confirm: can't reach GitHub (3s DNS timeout + render time)
Type "jip reach github.com"
Enter
Sleep 5500ms

# 4. Scan for a better network
Type "jip wifi"
Enter
Sleep 2500ms

# 5. Switch to the 5 GHz network
Type `jip use "Office_5G"`
Enter
Sleep 2000ms

# 6. Verify the fix
Type "jip reach github.com"
Enter
Sleep 2500ms
