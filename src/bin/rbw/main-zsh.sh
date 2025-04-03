_rbw_wrapper() {
  local -a opts
  local folder cur res

  if [[ "${words[2]}" == "get" ]]; then

    # rbw get

    for (( i=1; i < ${#words}; i++ )); do
      if [[ "${words[$(( i - 1 ))]}" == "--folder" ]]; then
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
    elif [[ "${words[-2]}" == "--folder" ]]; then
      # rbw get --folder $folder
      res=$(
        rbw list --fields folder \
          | awk -v folder="$folder" 'NF && $1 ~ folder {print $1}'
      )
    elif [[ "${words[-2]}" != "^--" ]]; then
      # rbw get ... $cur
      res=$(
        rbw list --fields name,folder \
        | awk -F'\t' -v name="$cur" -v folder="$folder" '$1 ~ name && $1 && $2 ~ folder {print $1}'
      )
    else
      _rbw
      return
    fi

    opts=("${(@f)${res}}")
    compadd -S '' -- "${opts[@]}"
  else
    _rbw
  fi


}

compdef _rbw_wrapper rbw
