VERSION = "0.3.0"

#? Wire format sizes
NONCE_SIZE = 12
TAG_SIZE = 16
KEY_SIZE = 32

#? Streaming
CHUNK_SIZE = 65536  #! 64 KiB

#? Archive format
ARCHIVE_MAGIC = b"ASH\x01"

#? Directory limits
MAX_DEPTH = 10
MAX_FILES = 10000
