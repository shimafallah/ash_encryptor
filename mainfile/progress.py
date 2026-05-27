import sys
import time

try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False


class ProgressReporter:

    def __init__(self, total_bytes: int, description: str = "Processing"):
        self.total_bytes = total_bytes
        self.description = description
        self.bytes_processed = 0
        self.start_time = time.time()

        if HAS_TQDM:
            self._bar = tqdm(
                total=total_bytes,
                desc=description,
                unit="B",
                unit_scale=True,
                unit_divisor=1024,
                file=sys.stderr,
                leave=True,
            )
        else:
            self._bar = None
            print(f"{description}: 0%", end="", file=sys.stderr)

    def update(self, bytes_processed: int) -> None:
        self.bytes_processed += bytes_processed
        if self._bar:
            self._bar.update(bytes_processed)
        else:
            pct = int(self.bytes_processed * 100 / self.total_bytes)
            print(f"\r{self.description}: {pct}%", end="", file=sys.stderr)

    def finish(self) -> None:
        elapsed = time.time() - self.start_time
        if self._bar:
            self._bar.close()
        else:
            print(f"\r{self.description}: 100%", file=sys.stderr)
        print(
            f"Done: {self.bytes_processed:,} bytes in {elapsed:.1f}s",
            file=sys.stderr,
        )

    def abort(self) -> None:
        if self._bar:
            self._bar.close()
        else:
            print("", file=sys.stderr)
