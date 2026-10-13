"""Entry point for the single-file executable (PyInstaller)."""
import sys

from netsentinel.__main__ import main

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
    except SystemExit:
        raise
    except Exception as ex:                      # keep the console open so the error can be read
        print(f"\nNetSentinel stopped: {ex}")
        input("Press Enter to close...")
        sys.exit(1)
