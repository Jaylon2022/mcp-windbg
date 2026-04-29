import subprocess
import threading
import re
import os
import platform
import signal
from typing import List, Optional

# Regular expression to detect CDB prompts
PROMPT_REGEX = re.compile(r"^\d+:\d+>\s*$")

# Command marker to reliably detect command completion
COMMAND_MARKER = ".echo COMMAND_COMPLETED_MARKER"
COMMAND_MARKER_PATTERN = re.compile(r"COMMAND_COMPLETED_MARKER")

# Default paths where cdb.exe might be located
DEFAULT_CDB_PATHS = [
    # Traditional Windows SDK locations
    r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe",
    r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x86\cdb.exe",
    r"C:\Program Files\Debugging Tools for Windows (x64)\cdb.exe",
    r"C:\Program Files\Debugging Tools for Windows (x86)\cdb.exe",

    # Microsoft Store WinDbg Preview locations (architecture-specific)
    os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\WindowsApps\cdbX64.exe"),
    os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\WindowsApps\cdbX86.exe"),
    os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\WindowsApps\cdbARM64.exe")
]

class CDBError(Exception):
    """Custom exception for CDB-related errors"""
    pass

class CDBSession:
    def __init__(
        self,
        dump_path: Optional[str] = None,
        remote_connection: Optional[str] = None,
        attach_process_id: Optional[int] = None,
        attach_process_name: Optional[str] = None,
        cdb_path: Optional[str] = None,
        symbols_path: Optional[str] = None,
        initial_commands: Optional[List[str]] = None,
        timeout: int = 10,
        verbose: bool = False,
        additional_args: Optional[List[str]] = None
    ):
        """
        Initialize a new CDB debugging session.

        Args:
            dump_path: Path to the crash dump file
            remote_connection: Remote debugging connection string (e.g., "tcp:Port=5005,Server=192.168.0.100")
            attach_process_id: PID of the local process to attach to
            attach_process_name: Name of the local process to attach to (e.g., "notepad.exe")
            cdb_path: Custom path to cdb.exe. If None, will try to find it automatically
            symbols_path: Custom symbols path. If None, uses default Windows symbols
            initial_commands: List of commands to run when CDB starts
            timeout: Timeout in seconds for waiting for CDB responses
            verbose: Whether to print additional debug information
            additional_args: Additional arguments to pass to cdb.exe

        Raises:
            CDBError: If cdb.exe cannot be found or started
            FileNotFoundError: If the dump file cannot be found
            ValueError: If invalid parameters are provided
        """
        # Validate that exactly one session type is provided
        provided = sum([
            bool(dump_path),
            bool(remote_connection),
            attach_process_id is not None,
            bool(attach_process_name),
        ])
        if provided == 0:
            raise ValueError("One of dump_path, remote_connection, attach_process_id, or attach_process_name must be provided")
        if provided > 1:
            raise ValueError("dump_path, remote_connection, attach_process_id, and attach_process_name are mutually exclusive")

        if dump_path and not os.path.isfile(dump_path):
            raise FileNotFoundError(f"Dump file not found: {dump_path}")

        self.dump_path = dump_path
        self.remote_connection = remote_connection
        self.attach_process_id = attach_process_id
        self.attach_process_name = attach_process_name
        self.timeout = timeout
        self.verbose = verbose

        # Find cdb executable
        self.cdb_path = self._find_cdb_executable(cdb_path)
        if not self.cdb_path:
            raise CDBError("Could not find cdb.exe. Please provide a valid path.")

        # Prepare command args
        cmd_args = [self.cdb_path]

        # Add connection type specific arguments
        if self.dump_path:
            cmd_args.extend(["-z", self.dump_path])
        elif self.remote_connection:
            cmd_args.extend(["-remote", self.remote_connection])
        elif self.attach_process_id is not None:
            cmd_args.extend(["-p", str(self.attach_process_id)])
        elif self.attach_process_name:
            cmd_args.extend(["-pn", self.attach_process_name])

        # Add symbols path if provided
        if symbols_path:
            cmd_args.extend(["-y", symbols_path])

        # Add any additional arguments
        if additional_args:
            cmd_args.extend(additional_args)

        try:
            # Create a new process group for sessions where CTRL+BREAK is needed
            creationflags = 0
            if os.name == 'nt' and (self.remote_connection or self.attach_process_id is not None or self.attach_process_name):
                creationflags = subprocess.CREATE_NEW_PROCESS_GROUP

            self.process = subprocess.Popen(
                cmd_args,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                creationflags=creationflags,
            )
        except Exception as e:
            raise CDBError(f"Failed to start CDB process: {str(e)}")

        self.output_lines = []
        self.lock = threading.Lock()
        self.ready_event = threading.Event()
        self._is_alive = True  # set to False when the CDB process exits
        self.reader_thread = threading.Thread(target=self._read_output)
        self.reader_thread.daemon = True
        self.reader_thread.start()

        # Wait for CDB to initialize by sending an echo marker
        try:
            self._wait_for_prompt(timeout=self.timeout)
        except CDBError:
            self.shutdown()
            raise CDBError("CDB initialization timed out")

        # Run initial commands if provided
        if initial_commands:
            for cmd in initial_commands:
                self.send_command(cmd)

    def _find_cdb_executable(self, custom_path: Optional[str] = None) -> Optional[str]:
        """Find the cdb.exe executable"""
        if custom_path and os.path.isfile(custom_path):
            return custom_path

        for path in DEFAULT_CDB_PATHS:
            if os.path.isfile(path):
                return path

        return None

    def _read_output(self):
        """Thread function to continuously read CDB output"""
        if not self.process or not self.process.stdout:
            return

        buffer = []
        try:
            for line in self.process.stdout:
                line = line.rstrip()
                if self.verbose:
                    print(f"CDB > {line}")

                with self.lock:
                    buffer.append(line)
                    # Check if the marker is in this line
                    if COMMAND_MARKER_PATTERN.search(line):
                        # Remove the marker line itself
                        if buffer and COMMAND_MARKER_PATTERN.search(buffer[-1]):
                            buffer.pop()
                        self.output_lines = buffer
                        buffer = []
                        self.ready_event.set()
        except (IOError, ValueError) as e:
            if self.verbose:
                print(f"CDB output reader error: {e}")
        finally:
            # Process has exited or stdout was closed. Unblock any send_command
            # that is currently waiting so it gets a CDBError instead of hanging
            # until timeout.
            self._is_alive = False
            self.ready_event.set()

    def _wait_for_prompt(self, timeout=None):
        """Wait for CDB to be ready for commands by sending a marker"""
        try:
            with self.lock:
                self.ready_event.clear()
                self.output_lines = []
            self.process.stdin.write(f"{COMMAND_MARKER}\n")
            self.process.stdin.flush()

            if not self.ready_event.wait(timeout=timeout or self.timeout):
                raise CDBError(f"Timed out waiting for CDB prompt")
            if not self._is_alive:
                raise CDBError("CDB process exited unexpectedly during initialization")
        except IOError as e:
            raise CDBError(f"Failed to communicate with CDB: {str(e)}")

    def send_command(self, command: str, timeout: Optional[int] = None) -> List[str]:
        """
        Send a command to CDB and return the output

        Args:
            command: The command to send
            timeout: Custom timeout for this command (overrides instance timeout)

        Returns:
            List of output lines from CDB

        Raises:
            CDBError: If the command times out or CDB is not responsive
        """
        if not self.process or not self._is_alive:
            raise CDBError("CDB process is not running")
        if self.process.poll() is not None:
            self._is_alive = False
            raise CDBError("CDB process has exited")

        with self.lock:
            self.ready_event.clear()  # inside lock to avoid race with reader thread
            self.output_lines = []

        try:
            # Send the command followed by our marker to detect completion
            self.process.stdin.write(f"{command}\n{COMMAND_MARKER}\n")
            self.process.stdin.flush()
        except IOError as e:
            raise CDBError(f"Failed to send command: {str(e)}")

        cmd_timeout = timeout or self.timeout
        if not self.ready_event.wait(timeout=cmd_timeout):
            raise CDBError(f"Command timed out after {cmd_timeout} seconds: {command}")

        if not self._is_alive:
            raise CDBError("CDB process exited unexpectedly while waiting for command output")

        with self.lock:
            result = self.output_lines.copy()
            self.output_lines = []
        return result

    def shutdown(self):
        """Clean up and terminate the CDB process"""
        try:
            if self.process and self.process.poll() is None:
                try:
                    if self.remote_connection:
                        # For remote client connections, 'qq' exits the client
                        # without killing the debug server or the target.
                        # 'q' would kill the target; \x02 written to stdin is
                        # not equivalent to pressing Ctrl+Break in a console.
                        self.process.stdin.write("qq\n")
                        self.process.stdin.flush()
                    elif self.attach_process_id is not None or self.attach_process_name:
                        # For local process attach, detach gracefully then quit
                        self.process.stdin.write(".detach\nq\n")
                        self.process.stdin.flush()
                    else:
                        # For dump files, send 'q' to quit
                        self.process.stdin.write("q\n")
                        self.process.stdin.flush()
                    self.process.wait(timeout=1)
                except Exception:
                    pass

                if self.process.poll() is None:
                    self.process.terminate()
                    self.process.wait(timeout=3)
        except Exception as e:
            if self.verbose:
                print(f"Error during shutdown: {e}")
        finally:
            self.process = None

    def send_ctrl_break(self) -> None:
        """Send a CTRL+BREAK event to the CDB process to break in.

        Raises:
            CDBError: If the signal cannot be delivered or the process is not running.
        """
        if not self.process or self.process.poll() is not None:
            raise CDBError("CDB process is not running")

        try:
            # On Windows, deliver CTRL+BREAK to the new process group we created
            self.process.send_signal(signal.CTRL_BREAK_EVENT)
        except Exception as e:
            raise CDBError(f"Failed to send CTRL+BREAK: {str(e)}")

    def get_session_id(self) -> str:
        """Get a unique identifier for this CDB session."""
        if self.dump_path:
            return os.path.abspath(self.dump_path)
        elif self.remote_connection:
            return f"remote:{self.remote_connection}"
        elif self.attach_process_id is not None:
            return f"pid:{self.attach_process_id}"
        elif self.attach_process_name:
            return f"process:{self.attach_process_name}"
        else:
            raise CDBError("Session has no valid identifier")

    def __enter__(self):
        """Support for context manager protocol"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Clean up when exiting context manager"""
        self.shutdown()
