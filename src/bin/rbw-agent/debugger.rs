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
        let e = std::io::Error::last_os_error();
        Err(anyhow::anyhow!("failed to disable PTRACE_ATTACH, agent memory may be dumpable by other processes: {e}"))
    }
}

#[cfg(target_os = "macos")]
pub fn disable_tracing() -> anyhow::Result<()> {
    // safety: correct arguments to ptrace
    // https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/ptrace.2.html
    let ret = unsafe { libc::ptrace(libc::PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0) };
    if ret != 0 {
        let e = std::io::Error::last_os_error();
        return Err(anyhow::anyhow!(
            "failed to deny debugger attach, agent memory may be readable by other processes: {}", e
        ));
    }

    // disable core dumps
    let rlim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // safety: correct argument
    // https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/setrlimit.2.html
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &rlim) };
    if ret != 0 {
        let e = std::io::Error::last_os_error();
        return Err(anyhow::anyhow!(
            "failed to disable core dumps, agent memory may be dumped to disk: {}", e
        ));
    }

    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn disable_tracing() -> anyhow::Result<()> {
    Err(anyhow::anyhow!("failed to disable PTRACE_ATTACH, agent memory may be dumpable by other processes: unimplemented on this platform"))
}