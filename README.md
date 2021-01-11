# RTStracer
RTStracer is a proof-of-concept DXE-Driver for [OVMF](https://github.com/tianocore/tianocore.github.io/wiki/OVMF) based on [EDK II](https://github.com/tianocore/tianocore.github.io/wiki/EDK-II).
It traces Runtime Service (RTS) calls in UEFI and demonstrates how to persist code in the RTSs to execute code.

## Implementation
In order to execute code after ExitBootServices was called, the driver is of the type DXE_RUNTIME_DRIVER.
The driver hooks all RTSs in the DXE phase and registers notifier whenever a RTS is called.
This gives us arbitirary code execution at runtime, for instance RTS traceing.
