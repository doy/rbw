_rbw_wrapper() {
  local cur prev folder opts res name user
  COMPREPLY=()

  if [[ "${COMP_WORDS[1]}" == "get" ]] && [[ $COMP_CWORD -gt 1 ]]; then
    for (( i=2; i < COMP_CWORD; i++ )); do
      case "${COMP_WORDS[i]}" in
        --folder|-f|--field)
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

    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

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
      fi
    done

    if [[ "$prev" == --folder ]]; then
      # rbw get --folder $folder
      res=$(
        rbw list --fields folder 2>/dev/null \
          | awk -v folder="$folder" 'NF && $1 ~ folder && !a[$1]++ {print $1}' 2>/dev/null
      )
    elif [[ "$prev" != --field ]]; then
      if [ -z "$name" ]; then
        # rbw get ... $cur
        res=$(
          rbw list --fields name,folder 2>/dev/null \
            | awk -F'\t' -v folder="$folder" '$1 && (!folder || $2 == folder) {print $1}' 2>/dev/null
        )
      elif [ -z "$user" ]; then
        # rbw get ... name $cur
        res=$(
          rbw list --fields name,folder,user 2>/dev/null \
            | awk -F'\t' -v name="$name" -v folder="$folder" '$1 == name && (!folder || $2 == folder) {print $3}' 2>/dev/null
        )
      fi
    else
      _rbw "$@"
      return
    fi

    if [[ "$cur" == -* ]]; then
      res="-f --field --full --raw --clipboard -i --ignorecase -h --help $res"
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
