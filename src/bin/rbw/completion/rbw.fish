function __fish_rbw_get
    set -l cmd (commandline -xpc)
    set -e cmd[1] # rbw

    argparse -i folder= f/field= full raw clipboard i/ignorecase h/help -- $cmd
    set -e argv[1] # get

    for entry in (rbw list --fields folder,name,user)
        set -l fields (string split \t "$entry")
        if not set -q _flag_folder || [ "$fields[1]" = "$_flag_folder" ]
            switch (count $argv)
                case 0
                    echo $fields[2]
                case 1
                    if [ "$fields[2]" = "$argv[1]" ]
                        echo $fields[3]
                    end
            end
        end
    end
end

complete -e -c rbw -n "__fish_rbw_using_subcommand get" -l folder -d 'Folder name to search in' -r
complete -c rbw -n "__fish_rbw_using_subcommand get" -l folder -d 'Folder name to search in' -r -f -a "(rbw list --fields folder)"
complete -c rbw -n "__fish_rbw_using_subcommand get" -f -a "(__fish_rbw_get)"
