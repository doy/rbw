_rbw_wrapper() {
  local -a opts
  local folder cur

  if [[ "${words[2]}" == "get" ]]; then

    # rbw get

    for (( i=1; i < ${#words}; i++ )); do
      if [[ "${words[$(( i - 1 ))]}" == "--folder" ]]; then
        # rbw get ... --folder $folder
        folder="${(Q)words[$i]}"
      fi
    done

    local cur="${(Q)words[CURRENT]}"

    if [[ "${words[-2]}" == "--folder" ]]; then
      [[ "$folder" != "$cur" ]] || return
      # rbw get --folder $cur
      local res=$(
        rbw list --fields folder \
        | awk -v folder="$cur" "NF && /$1/ {print}"
      )
      opts=("${(@f)${res}}")
    elif [[ "${words[-2]}" != "^--" ]]; then
      # rbw get ... $cur
      local res=$(
        rbw list --fields name,folder \
        | awk -F'\t' -v name="$cur" -v folder="$folder" '$1 ~ name && $1 && $2 ~ folder {print $1}'
      )
      opts=("${(@f)${res}}")
    else
      _rbw
      return
    fi

    compadd -S '' -- "${opts[@]}"
  else
    _rbw
  fi
}

compdef _rbw_wrapper rbw
