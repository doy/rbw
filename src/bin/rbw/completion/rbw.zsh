_rbw_wrapper() {
  local -a opts account_args
  local cur prev folder res name user account

  if [[ "${(Q)words[2]}" == "switch" ]] && [[ $CURRENT -eq 3 ]]; then
    res=$(
      rbw account list --raw 2>/dev/null \
        | awk -F'"' '/"name":/ {print $4}' 2>/dev/null
    )
    opts=("${(@f)${res}}")
    compadd -- "${opts[@]}"
    return
  fi

  if [[ "${(Q)words[2]}" == "account" ]] && [[ "${(Q)words[3]}" == ("switch"|"remove"|"rm"|"rename") ]] && [[ $CURRENT -eq 4 ]]; then
    res=$(
      rbw account list --raw 2>/dev/null \
        | awk -F'"' '/"name":/ {print $4}' 2>/dev/null
    )
    opts=("${(@f)${res}}")
    compadd -- "${opts[@]}"
    return
  fi

  if [[ "${(Q)words[CURRENT-1]}" == ("-a"|"--account") ]]; then
    res=$(
      rbw account list --raw 2>/dev/null \
        | awk -F'"' '/"name":/ {print $4}' 2>/dev/null
    )
    opts=("${(@f)${res}}")
    compadd -- "${opts[@]}"
    return
  fi

  if [[ "${(Q)words[2]}" == "get" ]] && [[ $CURRENT -gt 2 ]]; then
    for (( i=3; i < CURRENT; i++ )); do
      cur="${(Q)words[i]}"

      case "$cur" in
        --folder|-f|--field|-a|--account)
          (( i++ ))
          ;;
        -*)
          ;;
        *)
          if [ -z "$name" ]; then
            name="$cur"
          else
            user="$cur"
            break
          fi
          ;;
      esac
    done

    cur="${words[CURRENT]}"
    prev="${words[CURRENT-1]}"

    for (( i=3; i <= ${#words}; i++ )); do
      if [[ "${(Q)words[i-1]}" == "--folder" ]]; then
        folder="${(Q)words[i]}"
      elif [[ "${(Q)words[i]}" == "--folder="* ]]; then
        folder="${(Q)words[i]#--folder=}"
      elif [[ "${(Q)words[i-1]}" == ("-a"|"--account") ]]; then
        account="${(Q)words[i]}"
      elif [[ "${(Q)words[i]}" == "--account="* ]]; then
        account="${(Q)words[i]#--account=}"
      fi
    done

    if [ -n "$account" ]; then
      account_args=(--account "$account")
    fi

    if [[ "$prev" == "--folder" ]] || [[ "$cur" == "--folder="* ]]; then
      # rbw get --folder $folder
      res=$(
        rbw "${account_args[@]}" list --fields folder 2>/dev/null \
          | awk -v folder="$folder" 'NF && $1 ~ folder {print $1}' 2>/dev/null
      )
    elif [[ "$prev" != --field ]]; then
      if [ -z "$name" ]; then
        # rbw get ... $cur
        res=$(
          rbw "${account_args[@]}" list --fields name,folder 2>/dev/null \
            | awk -F'\t' -v folder="$folder" '$1 && (!folder || $2 == folder) {print $1}' 2>/dev/null
        )
      elif [ -z "$user" ]; then
        # rbw get ... name $cur
        res=$(
          rbw "${account_args[@]}" list --fields name,folder,user 2>/dev/null \
            | awk -F'\t' -v name="$name" -v folder="$folder" '$1 == name && (!folder || $2 == folder) {print $3}' 2>/dev/null
        )
      fi
    else
      _rbw
      return
    fi

    if [[ "$cur" == -* ]] && [[ "$cur" != "--folder="* ]]; then
      res=$'-a\n--account\n-f\n--field\n--full\n--raw\n--clipboard\n-i\n--ignorecase\n-h\n--help\n'"$res"
      if [ -z "$folder" ]; then
        res=$'--folder\n'"$res"
      fi
    fi

    opts=("${(@f)${res}}")
    if [[ "$cur" == "--folder="* ]]; then
      compadd -P '--folder=' -- "${opts[@]}"
    else
      compadd -- "${opts[@]}"
    fi
  else
    _rbw
  fi
}

compdef _rbw_wrapper rbw
