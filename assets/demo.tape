# assets/demo.gif, recorded with charmbracelet/vhs: `vhs assets/demo.tape`
#
# Records the real `ast` binary against a scratch ASTERISM_HOME so nothing
# touches ~/.asterism. Every line of output in the GIF is real program output.
# Boot waits are cut with Hide/Show, never faked.
#
# Before recording:
#   cargo build
#   export ASTERISM_HOME=/tmp/asterism-demo
#   mkdir -p "$ASTERISM_HOME/images" && ast pull debian:13
#   ast rm agent 2>/dev/null

Output assets/demo.gif

Set Shell zsh
Set FontFamily "Menlo"
Set FontSize 19
Set Width 1160
Set Height 460
Set Padding 26
Set Margin 0
Set BorderRadius 6
Set TypingSpeed 30ms
Set Framerate 12
Set Theme { "background": "#0A0B0D", "foreground": "#FAFAF8", "cursor": "#E7C87A", "selection": "#2A2C33", "black": "#101114", "red": "#D98A7A", "green": "#8FB98A", "yellow": "#E7C87A", "blue": "#8AA8CC", "magenta": "#C79AC0", "cyan": "#8FBDBD", "white": "#FAFAF8", "brightBlack": "#5A5C63", "brightRed": "#D98A7A", "brightGreen": "#8FB98A", "brightYellow": "#E7C87A", "brightBlue": "#8AA8CC", "brightMagenta": "#C79AC0", "brightCyan": "#8FBDBD", "brightWhite": "#FFFFFF" }

Hide
Type "export PATH=$PWD/target/debug:$PATH" Enter
Type "PROMPT='%F{#E7C87A}$%f '" Enter
Type "RPROMPT=''" Enter
Type "clear" Enter
Sleep 1s
Show

Sleep 600ms
Type "ast create agent --image debian:13" Sleep 400ms Enter
Sleep 900ms

Type "ast up agent" Sleep 300ms Enter
Sleep 1200ms

Type "ast ssh agent -- uname -a" Sleep 300ms Enter
Sleep 1300ms
Hide
Sleep 25s
Show
Sleep 1300ms

Type "ast down agent" Sleep 300ms Enter
Sleep 1200ms
Hide
Sleep 6s
Show
Sleep 500ms

Type "ast snapshot agent clean" Sleep 300ms Enter
Sleep 900ms

Type "ast ls" Sleep 300ms Enter
Sleep 1900ms
