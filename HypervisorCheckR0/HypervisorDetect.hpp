#pragma once
#include "NtApiDef.h"
 

/*
We can't use SEH for manual map driver's

*/

namespace DetectHyp
{
	

	 bool compare_list_cpuid() 
	{
		//compare cpuid  list
		int  invalid_cpuid_list[4] = { -1 };
		int valid_cpuid_list[4] = { -1 };

		__cpuid(invalid_cpuid_list, 0x13371337);
		__cpuid(valid_cpuid_list, 0x40000000);

		if ((invalid_cpuid_list[0] != valid_cpuid_list[0]) ||
			(invalid_cpuid_list[1] != valid_cpuid_list[1]) ||
			(invalid_cpuid_list[2] != valid_cpuid_list[2]) ||
			(invalid_cpuid_list[3] != valid_cpuid_list[3]))
			return true;

		return false; 



	}

	 bool cpuid_is_hypervisor()
	{
		int cpuid[4] = { 0 };
		__cpuid(cpuid, 1);
		return ((cpuid[2] >> 31) & 1);
	}



	  bool   time_attack_rdtsc()
	{ 
		_disable();
		unsigned long  tick1 = 0;
		unsigned long tick2 = 0;
		unsigned long avg = 0;
		int cpuInfo[4] = {};
		for (int i = 0; i < 1377; i++)
		{
			tick1 = __readmsr(IA32_TIME_STAMP_COUNTER);
			__cpuid(cpuInfo, 0);// vm-exit
			tick2 = __readmsr(IA32_TIME_STAMP_COUNTER);
			avg += (tick2 - tick1);
		}
		avg /=  1337;
		_enable();
		return (avg < 500 && avg > 25) ? false : true; 
	}

	 bool hypervisor_informathion()
	{
		
		SYSTEM_HYPERVISOR_QUERY_INFORMATION HypQueryInformathion{ -1 };
		ULONG retLenth = NULL;

		NtQuerySystemInformation(
			SystemHypervisorDetailInformation,
			&HypQueryInformathion,
			sizeof(SYSTEM_HYPERVISOR_QUERY_INFORMATION),
			&retLenth
		);

		return HypQueryInformathion.HypervisorPresent || HypQueryInformathion.HypervisorDebuggingEnabled;



	}

	 bool time_attack_rdtscp() {

		unsigned int  blabla = 0;
		DWORD tscp1 = 0;
		DWORD tscp2 = 0;
		DWORD avg = 0;
		INT cpuid[4] = { -1 };

		__cpuid(cpuid, 0x80000001);

		if ((cpuid[3] >> 27) & 1)//check support rdtscp
		{

			for (INT j = 0; j < 10; j++)
			{

				tscp1 = __rdtscp(&blabla);
				//call 3 cpuid for(vm-exxit) normal detect
				__cpuid(cpuid, 0);
				__cpuid(cpuid, 0);
				__cpuid(cpuid, 0);
				tscp2 = __rdtscp(&blabla);

				avg += tscp2 - tscp1;

				if (avg < 500 && avg > 25)
					return false;

				else
					avg = 0;

			}
			return true;
		}
		else
			return false; //rdtscp dont support
	}


	 bool time_attack_MPERF()
	{
		 // Some hypervisor just return 0(like:VMware)

		_disable();
			int cpuid[4]{ -1 };
			DWORD64  avg{ 0 };
			for (size_t i = 0; i < 1337; i++)
			{
				auto tick1 = __readmsr(IA32_MPERF_MSR);
				__cpuid(cpuid, 0);//call vm-exit
				auto tick2 = __readmsr(IA32_MPERF_MSR);
				avg += (tick2 - tick1);
			}
		_enable();
		avg /= 1337;
			return  (0xff < avg) || (0xc > avg);
	}
	


	 bool time_attack_APERF()
	{
		 // Some hypervisor just return 0(like:VMware)
		DWORD64 avg{ 0 };
		int data[4]{ -1 };
		_disable();
		for (size_t i = 0; i < 1337; i++)
		{
			DWORD64 tick1 = __readmsr(IA32_APERF_MSR) << 32;
			__cpuid(data, 0); //call vm-exit
			DWORD64 tick2 = __readmsr(IA32_APERF_MSR) << 32; 

			avg += (tick2 - tick1);

		} 
		_enable();
		avg /= 1337;
		return   (avg < 0x00000BE30000 ) || (avg > 0x00000FFF0000000);
	}
	
	 bool lbr_is_virtulazed()
	{
		DWORD64 current_value = __readmsr(MSR_DEBUGCTL);//safe current value
		__writemsr(MSR_DEBUGCTL, DEBUGCTL_LBR | DEBUGCTL_BTF);
		DWORD64 whatch_write = __readmsr(MSR_DEBUGCTL);
		__writemsr(MSR_DEBUGCTL, current_value);
		return (!(whatch_write & DEBUGCTL_LBR));
	}
 
	 bool lbr_stask_is_virtulazed()
	{
		int cpuid[4]{ -1 };
		 auto currentLBR =	__readmsr(MSR_P6M_LBSTK_TOS); 
		 __cpuid(cpuid, 0);//call vm-exit
		 auto exitLBR =	__readmsr(MSR_P6M_LBSTK_TOS); 
		 return currentLBR != exitLBR;

	}

	
	 DWORD64 vary_lazy_hypervisor()
	{
		/*
		if IA32_P5_MC_ADDR_MSR or SMI_COUNT_MSR just return 0,then this hypervisor very lazy
		
		*/
		int cpuid[4]{ -1 };
		auto smi_count = __readmsr(SMI_COUNT_MSR);
		auto p5_mc_addr = __readmsr(IA32_P5_MC_ADDR_MSR);
		return (smi_count == 0 ) &&   (p5_mc_addr ==0);
	}
	 
	
}