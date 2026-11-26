_rbw_wrapper() {
  local cur prev folder opts res name user account
  local -a account_args=()
  COMPREPLY=()

  cur="${COMP_WORDS[COMP_CWORD]}"
  prev="${COMP_WORDS[COMP_CWORD-1]}"

  if [[ "$prev" == "-a" || "$prev" == "--account" ]] || \
     ([[ "${COMP_WORDS[1]}" == "switch" ]] && [[ $COMP_CWORD -eq 2 ]]) || \
     ([[ "${COMP_WORDS[1]}" == "account" ]] && [[ "${COMP_WORDS[2]}" =~ ^(switch|remove|rm|rename)$ ]] && [[ $COMP_CWORD -eq 3 ]]); then
    res=$(
      rbw account list --raw 2>/dev/null \
        | awk -F'"' '/"name":/ {print $4}' 2>/dev/null
    )
    mapfile -t opts <<< "$res"
    COMPREPLY=( $(compgen -W "${opts[*]}" -- "$cur") )
    return 0
  fi

  if [[ "${COMP_WORDS[1]}" == "get" ]] && [[ $COMP_CWORD -gt 1 ]]; then
    for (( i=2; i < COMP_CWORD; i++ )); do
      case "${COMP_WORDS[i]}" in
        --folder|-f|--field|-a|--account)
          (( i++ ))
          if [ "${COMP_WORDS[i]}" == "=" ]; then
            (( i++ ))
          fi
          ;;
        -*)
          ;;
        *)
          if [ -z "$name" ]; then
            name="${COMP_WORDS[i]}"
          else
            user="${COMP_WORDS[i]}"
            break
          fi
          ;;
      esac
    done

    for (( i=2; i < ${#COMP_WORDS[@]}; i++ )); do
      if [[ "${COMP_WORDS[i-2]}" == "--folder" ]] && [[ "${COMP_WORDS[i-1]}" == "=" ]]; then
        folder="${COMP_WORDS[i]}"
        if [[ $i -eq $COMP_CWORD ]]; then
          prev="--folder"
        fi
      elif [[ "${COMP_WORDS[i-1]}" == "--folder" ]] && [[ "${COMP_WORDS[i]}" == "=" ]]; then
        folder=""
        if [[ $i -eq $COMP_CWORD ]]; then
          prev="--folder"
          cur=""
        fi
      elif [[ "${COMP_WORDS[i-1]}" == "--folder" ]]; then
        folder="${COMP_WORDS[i]}"
      elif [[ "${COMP_WORDS[i-1]}" == "-a" || "${COMP_WORDS[i-1]}" == "--account" ]]; then
        account="${COMP_WORDS[i]}"
      fi
    done

    if [ -n "$account" ]; then
      account_args=(--account "$account")
    fi

    if [[ "$prev" == --folder ]]; then
      # rbw get --folder $folder
      res=$(
        rbw "${account_args[@]}" list --fields folder 2>/dev/null \
          | awk -v folder="$folder" 'NF && $1 ~ folder && !a[$1]++ {print $1}' 2>/dev/null
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
      _rbw "$@"
      return
    fi

    if [[ "$cur" == -* ]]; then
      res="-a --account -f --field --full --raw --clipboard -i --ignorecase -h --help $res"
      if [ -z "$folder" ]; then
        res="--folder $res"
      fi
    fi

    mapfile -t opts <<< "$res"
    COMPREPLY=( $(compgen -W "${opts[*]}" -- "$cur") )
    return 0
  else
    _rbw "$@"
  fi
}

if [[ "${BASH_VERSINFO[0]}" -eq 4 && "${BASH_VERSINFO[1]}" -ge 4 || "${BASH_VERSINFO[0]}" -gt 4 ]]; then
    complete -F _rbw_wrapper -o nosort -o bashdefault -o default rbw
else
    complete -F _rbw_wrapper -o bashdefault -o default rbw
fi
