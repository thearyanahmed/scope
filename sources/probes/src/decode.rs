//! kvm_exit reason names. The kernel side packs `primary | aux << 16`:
//! x86: primary = exit_reason, aux = isa (1 VMX, 2 SVM);
//! arm64: primary = esr_ec, aux = ret (ARM_EXCEPTION_*).
//! Sources: Intel SDM vol. 3 appendix C, AMD APM vol. 2 appendix C,
//! Arm ARM D17.2.37 (ESR_ELx.EC), arch/arm64/include/asm/kvm_asm.h.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arch {
    X86_64,
    Aarch64,
}

impl Arch {
    pub const HOST: Option<Arch> = if cfg!(target_arch = "x86_64") {
        Some(Arch::X86_64)
    } else if cfg!(target_arch = "aarch64") {
        Some(Arch::Aarch64)
    } else {
        None
    };

    /// (primary, aux, pc) field names in the kvm_exit tracepoint.
    pub fn exit_fields(self) -> (&'static str, &'static str, &'static str) {
        match self {
            Arch::X86_64 => ("exit_reason", "isa", "guest_rip"),
            Arch::Aarch64 => ("esr_ec", "ret", "vcpu_pc"),
        }
    }
}

pub fn decode(arch: Arch, packed: u32) -> String {
    let (primary, aux) = (packed & 0xffff, packed >> 16);
    match arch {
        Arch::X86_64 => match aux {
            2 => svm(primary),
            _ => vmx(primary).map_or_else(|| format!("VMX_{primary}"), str::to_owned),
        },
        Arch::Aarch64 => match aux {
            0 => "IRQ".into(),
            1 => "EL1_SERROR".into(),
            3 => "ILLEGAL".into(),
            4 => "HYP_REQ".into(),
            _ => ec(primary).map_or_else(|| format!("EC_{primary:#04x}"), |n| n.to_owned()),
        },
    }
}

fn vmx(r: u32) -> Option<&'static str> {
    Some(match r {
        0 => "EXCEPTION_NMI",
        1 => "EXTERNAL_INTERRUPT",
        2 => "TRIPLE_FAULT",
        3 => "INIT_SIGNAL",
        4 => "SIPI",
        7 => "INTERRUPT_WINDOW",
        8 => "NMI_WINDOW",
        9 => "TASK_SWITCH",
        10 => "CPUID",
        12 => "HLT",
        13 => "INVD",
        14 => "INVLPG",
        15 => "RDPMC",
        16 => "RDTSC",
        18 => "VMCALL",
        28 => "CR_ACCESS",
        29 => "DR_ACCESS",
        30 => "IO_INSTRUCTION",
        31 => "MSR_READ",
        32 => "MSR_WRITE",
        33 => "INVALID_STATE",
        36 => "MWAIT",
        37 => "MONITOR_TRAP_FLAG",
        39 => "MONITOR",
        40 => "PAUSE",
        41 => "MCE_DURING_VMENTRY",
        43 => "TPR_BELOW_THRESHOLD",
        44 => "APIC_ACCESS",
        45 => "EOI_INDUCED",
        46 => "GDTR_IDTR",
        47 => "LDTR_TR",
        48 => "EPT_VIOLATION",
        49 => "EPT_MISCONFIG",
        50 => "INVEPT",
        51 => "RDTSCP",
        52 => "PREEMPTION_TIMER",
        53 => "INVVPID",
        54 => "WBINVD",
        55 => "XSETBV",
        56 => "APIC_WRITE",
        57 => "RDRAND",
        58 => "INVPCID",
        59 => "VMFUNC",
        60 => "ENCLS",
        61 => "RDSEED",
        62 => "PML_FULL",
        63 => "XSAVES",
        64 => "XRSTORS",
        67 => "UMWAIT",
        68 => "TPAUSE",
        74 => "BUS_LOCK",
        75 => "NOTIFY",
        _ => return None,
    })
}

fn svm(c: u32) -> String {
    let named = match c {
        0x60 => "INTR",
        0x61 => "NMI",
        0x62 => "SMI",
        0x63 => "INIT",
        0x64 => "VINTR",
        0x65 => "CR0_SEL_WRITE",
        0x6e => "RDTSC",
        0x6f => "RDPMC",
        0x72 => "CPUID",
        0x74 => "IRET",
        0x76 => "INVD",
        0x77 => "PAUSE",
        0x78 => "HLT",
        0x79 => "INVLPG",
        0x7b => "IOIO",
        0x7c => "MSR",
        0x7d => "TASK_SWITCH",
        0x7f => "SHUTDOWN",
        0x81 => "VMMCALL",
        0x87 => "RDTSCP",
        0x89 => "WBINVD",
        0x8a => "MONITOR",
        0x8b => "MWAIT",
        0x8d => "XSETBV",
        0x8f => "EFER_WRITE_TRAP",
        0x400 => "NPF",
        0x401 => "AVIC_INCOMPLETE_IPI",
        0x402 => "AVIC_UNACCELERATED_ACCESS",
        0x403 => "VMGEXIT",
        0x00..=0x0f => return format!("READ_CR{c}"),
        0x10..=0x1f => return format!("WRITE_CR{}", c - 0x10),
        0x20..=0x2f => return format!("READ_DR{}", c - 0x20),
        0x30..=0x3f => return format!("WRITE_DR{}", c - 0x30),
        0x40..=0x5f => return format!("EXCP_{}", c - 0x40),
        _ => return format!("SVM_{c:#x}"),
    };
    named.to_owned()
}

fn ec(e: u32) -> Option<&'static str> {
    Some(match e {
        0x00 => "UNKNOWN",
        0x01 => "WFX",
        0x03 => "CP15_32",
        0x04 => "CP15_64",
        0x05 => "CP14_MR",
        0x06 => "CP14_LS",
        0x07 => "FP_ASIMD",
        0x0c => "CP14_64",
        0x0e => "ILL",
        0x11 => "SVC32",
        0x12 => "HVC32",
        0x13 => "SMC32",
        0x15 => "SVC64",
        0x16 => "HVC64",
        0x17 => "SMC64",
        0x18 => "SYS64",
        0x19 => "SVE",
        0x1a => "ERET",
        0x1e => "FPAC",
        0x20 => "IABT_LOW",
        0x21 => "IABT_CUR",
        0x22 => "PC_ALIGN",
        0x24 => "DABT_LOW",
        0x25 => "DABT_CUR",
        0x26 => "SP_ALIGN",
        0x28 => "FP_EXC32",
        0x2c => "FP_EXC64",
        0x2f => "SERROR",
        0x30 => "BREAKPT_LOW",
        0x32 => "SOFTSTP_LOW",
        0x34 => "WATCHPT_LOW",
        0x38 => "BKPT32",
        0x3c => "BRK64",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x86() {
        assert_eq!(decode(Arch::X86_64, 30 | 1 << 16), "IO_INSTRUCTION");
        assert_eq!(decode(Arch::X86_64, 48 | 1 << 16), "EPT_VIOLATION");
        assert_eq!(decode(Arch::X86_64, 999 | 1 << 16), "VMX_999");
        assert_eq!(decode(Arch::X86_64, 0x7b | 2 << 16), "IOIO");
        assert_eq!(decode(Arch::X86_64, 0x400 | 2 << 16), "NPF");
        assert_eq!(decode(Arch::X86_64, 0x13 | 2 << 16), "WRITE_CR3");
        assert_eq!(decode(Arch::X86_64, 0x4e | 2 << 16), "EXCP_14");
    }

    #[test]
    fn arm64() {
        assert_eq!(decode(Arch::Aarch64, 0x24 | 2 << 16), "DABT_LOW");
        assert_eq!(decode(Arch::Aarch64, 0x01 | 2 << 16), "WFX");
        assert_eq!(decode(Arch::Aarch64, 0x24), "IRQ", "non-trap exits are named by ret");
        assert_eq!(decode(Arch::Aarch64, 0x3f | 2 << 16), "EC_0x3f");
    }
}
