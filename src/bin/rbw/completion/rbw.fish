function __fish_rbw_get_completion_name
    set -l cmd (commandline -xpc)
    set -e cmd[1] # rbw

    argparse -i folder= f/field= full raw clipboard i/ignorecase h/help l/list-fields -- $cmd
    set -e argv[1] # get

    set -l canidates (command rbw list --fields name,folder,user)
    # if folder is set, filter by it
    if set -q _flag_folder
        set canidates (printf '%s\n' $canidates | string match -er "^[^\t]*\t$_flag_folder\t")
    end

    switch (count $argv)
        case 0
            # print completion for NAME argument in the format of
            # NAME   (USERNAME [FOLDER])
            printf '%s\n' $canidates | while read -l line
                set --local parts (string split \t $line)

                set --local _name $parts[1]
                set --local _folder $parts[2]
                set --local _user $parts[3]

                if test -n "$_folder"
                    printf '%s\t%s [%s]\n' $_name $_user $_folder
                else
                    printf '%s\t%s\n' $_name $_user
                end
            end
        case 1
            # filter by NAME
            set canidates (printf '%s\n' $canidates | string match -er "^$argv[1]\t")
            # print completion for USER argument in the format of
            # USER   ([FOLDER])
            printf '%s\n' $canidates | while read -l line
                set --local parts (string split \t $line)

                set --local _user $parts[3]
                if test "$_user" != ""
                    # non-empty
                    set --local _folder $parts[2]
                    if test -n "$_folder"
                        printf '%s\t[%s]\n' $_user $_folder
                    else
                        printf '%s\n' $_user
                    end
                end
            end
    end
end

function __fish_rbw_get_completion_fields
    set -l cmd (commandline -xpc)
    set -e cmd[1] # rbw

    argparse -i folder= full raw clipboard i/ignorecase h/help l/list-fields -- $cmd

    if test (count $argv) -gt 0
        set -e argv[1] # get

        command rbw get "$argv[1]" --list-fields
    end
end

complete -f -c rbw -n '__fish_seen_subcommand_from get edit' -a '(__fish_rbw_get_completion_name)'

# Complete options for `rbw get`
complete -f -c rbw -n '__fish_seen_subcommand_from get' -s i -l ignorecase -d 'Ignore case'
complete -f -c rbw -n '__fish_seen_subcommand_from get' -s f -l field -r -d 'Field to get' -a '(__fish_rbw_get_completion_fields)'
complete -f -c rbw -n '__fish_seen_subcommand_from get' -s l -l list-fields -r -d 'List fields in this entry'
complete -f -c rbw -n '__fish_seen_subcommand_from get' -l folder -r -d 'Folder name to search in' -a '(command rbw list --fields folder)'
complete -f -c rbw -n '__fish_seen_subcommand_from get' -l full -d 'Display the notes in addition to the password'
complete -f -c rbw -n '__fish_seen_subcommand_from get' -l raw -d 'Display output as JSON'
complete -f -c rbw -n '__fish_seen_subcommand_from get' -s c -l clipboard -d 'Copy result to clipboard'
complete -f -c rbw -n '__fish_seen_subcommand_from get' -s h -l help -d 'Print help'
