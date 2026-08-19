# Bash completion for sv.
#
# Install: source this file from ~/.bashrc, or drop it into
# /etc/bash_completion.d/ (or $(brew --prefix)/etc/bash_completion.d/).
# Targets complete from the short names in
# ~/.config/svartal/shortnames.json — the same file `sv name` writes — so a
# completion never costs a network round trip.

_sv_shortnames() {
  local state_dir=${SVARTAL_CONFIG_DIR:-${XDG_CONFIG_HOME:-$HOME/.config}/svartal}
  local file=$state_dir/shortnames.json
  [[ -r $file ]] || return
  sed -n 's/^[[:space:]]*"\([^"]*\)".*/\1/p' "$file" 2>/dev/null
}

_sv() {
  local cur=${COMP_WORDS[COMP_CWORD]}
  local command=${COMP_WORDS[1]}

  if [[ $COMP_CWORD -eq 1 ]]; then
    COMPREPLY=($(compgen -W "login logout whoami machines envs add name sessions shell claude close help" -- "$cur"))
    return
  fi

  if [[ $cur == -* ]]; then
    local flags=""
    case $command in
      login) flags="--no-browser" ;;
      whoami|machines|envs|sessions) flags="--json" ;;
      add) flags="--json --origin --publish-only --print-token --token-file" ;;
      name) flags="--remove" ;;
      shell|claude|close) flags="--terminal-id" ;;
    esac
    COMPREPLY=($(compgen -W "$flags" -- "$cur"))
    return
  fi

  case $command in
    shell|claude|sessions)
      COMPREPLY=($(compgen -W "$(_sv_shortnames)" -- "$cur"))
      ;;
    name)
      COMPREPLY=($(compgen -W "$(_sv_shortnames)" -- "$cur"))
      ;;
    close)
      if [[ $COMP_CWORD -eq 2 ]]; then
        COMPREPLY=($(compgen -W "shell claude" -- "$cur"))
      else
        COMPREPLY=($(compgen -W "$(_sv_shortnames)" -- "$cur"))
      fi
      ;;
  esac
}

complete -F _sv sv
