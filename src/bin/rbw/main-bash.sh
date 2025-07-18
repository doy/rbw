_rbw_wrapper() {
  local cur prev folder opts res
  COMPREPLY=()

  if [[ "${COMP_WORDS[1]}" == "get" ]]; then

    # rbw get

    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    for (( i=1; i < ${#COMP_WORDS[@]}; i++ )); do
      if [[ "${COMP_WORDS[i-2]}" == "--folder" ]] && [[ "${COMP_WORDS[i-1]}" == "=" ]]; then
        folder="${COMP_WORDS[i]}"
        if [[ $i -eq $(( COMP_CWORD - 1 )) ]]; then
          prev="--folder"
        fi
      elif [[ "${COMP_WORDS[i-1]}" == "--folder" ]] && [[ "${COMP_WORDS[i]}" == "=" ]]; then
        folder=""
        if [[ $i -eq $(( COMP_CWORD - 1 )) ]]; then
          prev="--folder"
          cur=""
        fi
      elif [[ "${COMP_WORDS[i-1]}" == "--folder" ]]; then
        folder="${COMP_WORDS[i]}"
      fi
    done

    if [[ "$prev" == --folder ]]; then
      # rbw get --folder $folder
      res=$(
        rbw list --fields folder 2>/dev/null \
          | awk -v folder="$folder" 'NF && $1 ~ folder {print $1}'
      )

      # Split output into an array (one entry per line)
    elif [[ "$prev" != ^-- ]]; then
      # rbw get ... $cur
      res=$(
        rbw list --fields name,folder 2>/dev/null \
          | awk -F'\t' -v name="$cur" -v folder="$folder" '$1 ~ name && $1 && $2 ~ folder {print $1}'
      )
    else
      return 0
    fi

    mapfile -t opts <<< "$res"
    COMPREPLY=( $(compgen -W "${opts[*]}" -- "$cur") )
    return 0
  else
    return 0
  fi
}

complete -F _rbw_wrapper rbw
