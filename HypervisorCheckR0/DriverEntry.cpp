#include "HypervisorDetect.hpp"



NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriverObject, IN PUNICODE_STRING pRegistryPath)
{
	UNREFERENCED_PARAMETER(pRegistryPath);


	
	DbgPrint("[Bad lev1oto] SYSTEM_HYPERVISOR_QUERY_INFORMATION ->\t 0x%p\n", DetectHyp::hypervisor_informathion());
	DbgPrint("[Bad lev1oto] Cpuid is hypervisor ->\t 0x%p\n", DetectHyp::cpuid_is_hypervisor());
	DbgPrint("[Bad lev1oto] Compare cpuid list ->\t 0x%p\n", DetectHyp::compare_list_cpuid());
	DbgPrint("[Bad lev1oto] Time attack with rdtsc ->\t 0x%p\n", DetectHyp::time_attack_rdtsc());
	DbgPrint("[Bad lev1oto] Time attack with rdtscp ->\t 0x%p\n", DetectHyp::time_attack_rdtscp());
	DbgPrint("[Bad lev1oto] Time attack with APERF ->\t 0x%p\n", DetectHyp::time_attack_APERF());
	DbgPrint("[Bad lev1oto] Time attack with MPERF->\t 0x%p\n", DetectHyp::time_attack_MPERF());
	DbgPrint("[Bad lev1oto] LBR is virtualizate ->\t 0x%p\n", DetectHyp::lbr_is_virtulazed());
	DbgPrint("[Bad lev1oto] LBR stack check ->\t 0x%p\n", DetectHyp::lbr_stask_is_virtulazed());
	DbgPrint("[Bad lev1oto] Read non zero value ->\t 0x%p\n", DetectHyp::very_lazy_hypervisor());
	
	return STATUS_SUCCESS;
}
