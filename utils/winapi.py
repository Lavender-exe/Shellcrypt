import ctypes
from ctypes import wintypes

# ---------- NTAPI RTL prototypes -------------------------------------------------
ntdll = ctypes.windll.ntdll

# NTSTATUS NTAPI RtlGetCompressionWorkSpaceSize(
#     _In_  USHORT CompressionFormatAndEngine,
#     _Out_ PULONG CompressBufferWorkSpaceSize,
#     _Out_ PULONG CompressBufferFragmentWorkSpaceSize
# );
RtlGetCompressionWorkSpaceSize = ntdll.RtlGetCompressionWorkSpaceSize
RtlGetCompressionWorkSpaceSize.argtypes = [
    wintypes.USHORT,
    ctypes.POINTER(wintypes.ULONG),
    ctypes.POINTER(wintypes.ULONG),
]
RtlGetCompressionWorkSpaceSize.restype = wintypes.LONG

# NTSTATUS NTAPI RtlCompressBuffer(
#     _In_  USHORT CompressionFormatAndEngine,
#     _In_  PUCHAR UncompressedBuffer,
#     _In_  ULONG  UncompressedBufferSize,
#     _Out_ PUCHAR CompressedBuffer,
#     _In_  ULONG  CompressedBufferSize,
#     _In_  ULONG  UncompressedChunkSize,
#     _Out_ PULONG FinalCompressedSize,
#     _In_  PVOID  WorkSpace
# );
RtlCompressBuffer = ntdll.RtlCompressBuffer
RtlCompressBuffer.argtypes = [
    wintypes.USHORT,
    wintypes.LPVOID,
    wintypes.ULONG,
    wintypes.LPVOID,
    wintypes.ULONG,
    wintypes.ULONG,
    ctypes.POINTER(wintypes.ULONG),
    wintypes.LPVOID,
]
RtlCompressBuffer.restype = wintypes.LONG

# NTSTATUS NTAPI RtlDecompressBuffer(
#     _Out_ PUCHAR UncompressedBuffer,
#     _In_  ULONG  UncompressedBufferSize,
#     _In_  PUCHAR CompressedBuffer,
#     _In_  ULONG  CompressedBufferSize,
#     _Out_ PULONG FinalUncompressedSize
# );
RtlDecompressBuffer = ntdll.RtlDecompressBuffer
RtlDecompressBuffer.argtypes = [
    wintypes.LPVOID,
    wintypes.ULONG,
    wintypes.LPVOID,
    wintypes.ULONG,
    ctypes.POINTER(wintypes.ULONG),
]
RtlDecompressBuffer.restype = wintypes.LONG

# ---------- constants ---------------------------------------------------------
COMPRESSION_FORMAT_LZNT1     = 0x0002
COMPRESSION_ENGINE_MAXIMUM = 0x0100
COMPRESSION_FORMAT_AND_ENGINE = COMPRESSION_FORMAT_LZNT1 | COMPRESSION_ENGINE_MAXIMUM