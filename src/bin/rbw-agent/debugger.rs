// Prevent other user processes from attaching to the rbw agent and dumping
// memory This is not perfect protection, but closes a door. Unfortunately,
// prctl only works on Linux.
#[cfg(target_os = "linux")]
pub fn disable_tracing() -> anyhow::Result<()> {
    // https://github.com/torvalds/linux/blob/v5.11/include/uapi/linux/prctl.h#L14
    const PR_SET_DUMPABLE: i32 = 4;

    // safe because it's just a raw call to prctl, and the arguments are
    // correct
    let ret = unsafe { libc::prctl(PR_SET_DUMPABLE, 0) };
    if ret == 0 {
        Ok(())
    } else {
        Err(anyhow::anyhow!("rbw-agent: Failed to disable PTRACE_ATTACH. Agent memory may be dumpable by other processes."))
    }
}

#[cfg(not(target_os = "linux"))]
pub fn disable_tracing() -> anyhow::Result<()> {
    Err(anyhow::anyhow!("rbw-agent: Unable to disable PTRACE_ATTACH on this platform: not implemented. Agent memory may be dumpable by other processes."))
}
