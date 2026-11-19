fn main() -> Result<(), Box<dyn std::error::Error>> {
    // sets cfg(bpf_target_arch = ...) so arch-specific code can be gated.
    aya_build::emit_bpf_target_arch_cfg()?;
    Ok(())
}
