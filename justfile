build:
  cargo build

ls:
  cargo run --bin rbw -- list --fields=id,name,user,folder,type

fresh_test:
  @killall -9 rbw-agent || exit 0
  @cargo run --bin rbw-agent
  cargo run --bin rbw -- unlock
  
rbw args:
  @cargo run --bin rbw -- {{args}}

