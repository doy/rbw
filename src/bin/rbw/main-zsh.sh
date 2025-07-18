_rbw_wrapper() {
  local -a opts
  local cur prev folder res

  if [[ "${words[2]}" == "get" ]]; then

    # rbw get

    for (( i=1; i < ${#words}; i++ )); do
      cur="${words[$i]}"
      if [[ "$cur" == --folder=* ]]; then
        # rbw get ... --folder $folder
        folder="${cur#--folder=}"
        folder="${(Q)folder}"
      elif [[ "${words[$(( i - 1 ))]}" == --folder ]]; then
        # rbw get ... --folder $folder
        folder="${(Q)words[$i]}"
        prefix=""
      fi
    done

    local cur="${(Q)words[CURRENT]}"

    if [[ "$cur" == "--folder"* ]]; then
      # rbw get --folder=$folder
      if [[ "$cur" != "--folder" ]]; then
        folder="${cur#--folder=}"
        folder="${(Q)folder}"
      fi
      res=$(
        rbw list --fields folder \
          | awk -v folder="$folder" 'NF && $1 ~ folder {print "--folder=" $1}'
         )
    elif [[ "$prev" == "--folder" ]]; then
      # rbw get --folder $folder
      res=$(
        rbw list --fields folder \
          | awk -v folder="$folder" 'NF && $1 ~ folder {print $1}'
      )
    elif [[ "$prev" != -* ]] && [[ "$cur" != -* ]]; then
      # rbw get ... $cur
      res=$(
        rbw list --fields name,folder \
        | awk -F'\t' -v name="$cur" -v folder="$folder" '$1 ~ name && $1 && $2 ~ folder {print $1}'
      )
    else
      _rbw
      return
    fi

    if [[ "$res" == "$cur" ]]; then
      compadd -S '' -- "${opts[@]}"
    else
      opts=("${(@f)${res}}")
      compadd -S '' -- "${opts[@]}"
    fi
  else
    _rbw
  fi

}

compdef _rbw_wrapper rbw
