Measurements obtained with tpm_benchmarks.sh
==


Machine: slmilan01
--

Machine description:
* (TBD)
* Softlayer

Setup #1: SVSM virtual machine.
--

```
===> TPM manufacturer: "MSFT"
===> pcrread test 
     repeats:               3000
     test duration:         10 s
     pcrread latency:       3582 usecs
===> pcrextend test 
     repeats:               3000
     test duration:         7 s
     pcrextend latency:     2570 usecs
===> tpm2_quote test 
     repeats:               1000
     Prep exit code:        0
     test duration:         10 s
     tpm2_quote latency:    10844 usecs
===> createprimary (ECC) test
     repeats:               100
     test duration:         0 s
     createprimary latency: 9015 usecs
```

Setup #2: same VM guest running with swtpm vTPM over socket.
--

```
===> TPM manufacturer: "IBM"
===> pcrread test 
     repeats:               3000
     test duration:         54 s
     pcrread latency:       18254 usecs
===> pcrextend test 
     repeats:               3000
     test duration:         14 s
     pcrextend latency:     4845 usecs
===> tpm2_quote test 
     repeats:               1000
     Prep exit code:        0
     test duration:         56 s
     tpm2_quote latency:    56783 usecs
===> createprimary (ECC) test
     repeats:               100
     test duration:         3 s
     createprimary latency: 34438 usecs
```
