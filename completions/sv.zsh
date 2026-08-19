#compdef sv
# Zsh completion for sv.
#
# Install: put this file in a directory on $fpath as `_sv`, or source it from
# ~/.zshrc. Targets complete from the short names in
# ~/.config/svartal/shortnames.json — the same file `sv name` writes — so a
# completion never costs a network round trip.

_sv_shortnames() {
  local state_dir=${SVARTAL_CONFIG_DIR:-${XDG_CONFIG_HOME:-$HOME/.config}/svartal}
  local file=$state_dir/shortnames.json
  [[ -r $file ]] || return
  local -a names
  names=(${(f)"$(sed -n 's/^[[:space:]]*"\([^"]*\)".*/\1/p' "$file" 2>/dev/null)"})
  (( ${#names} )) && _describe -t shortnames 'short name' names
}

_sv() {
  local -a commands
  commands=(
    'login:Sign in to Svartal in this terminal'
    'logout:Revoke this terminal'\''s Svartal credential and delete it'
    'whoami:Show who this terminal is signed in as'
    'machines:List the machines and workspaces you can reach'
    'envs:List your environments, with their short names'
    'add:Link this machine with a pairing URL, or show how a new box joins'
    'name:Name an environment, or list the names you have given'
    'sessions:List agent sessions on a machine'
    'shell:Open a shell in a workspace you can reach'
    'claude:Open an interactive Claude terminal in a workspace'
    'close:End a shell or Claude terminal without attaching to it'
    'help:Show the usage'
  )

  if (( CURRENT == 2 )); then
    _describe -t commands 'sv command' commands
    return
  fi

  case $words[2] in
    login)
      _arguments '--no-browser[print the sign-in URL instead of opening a browser]'
      ;;
    whoami|machines|envs)
      _arguments '--json[emit JSON instead of a table]'
      ;;
    sessions)
      _arguments '--json[emit JSON instead of a table]' '2:machine:_sv_shortnames'
      ;;
    add)
      _arguments \
        '--json[emit JSON instead of the runbook]' \
        '--origin[the loopback origin the new box'\''s environment server listens on]:origin url:' \
        '--publish-only[write the runbook for a box with no managed tunnel]' \
        '--print-token[write only a Svartal access token to stdout]' \
        '--token-file[write that token to a 0600 file instead]:token file:_files' \
        '2:pairing url:'
      ;;
    name)
      _arguments '--remove[forget a short name]:short name:_sv_shortnames' \
        '2:short name:_sv_shortnames' '3:workspace:_sv_shortnames'
      ;;
    shell|claude)
      _arguments '--terminal-id[open a second, separate terminal on the same workspace]:terminal id:' \
        '2:target:_sv_shortnames'
      ;;
    close)
      if (( CURRENT == 3 )); then
        local -a kinds
        kinds=('shell:end the shell on a workspace' 'claude:end the Claude terminal on a workspace')
        _describe -t kinds 'what to close' kinds
      else
        _arguments '--terminal-id[close that separate terminal instead]:terminal id:' \
          '3:target:_sv_shortnames'
      fi
      ;;
  esac
}

_sv "$@"
