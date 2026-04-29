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

# Default paths where cdb.exe might be located (user-mode debugging)
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

# Default paths where kd.exe might be located (kernel-mode debugging).
# kd.exe lives in the same directories as cdb.exe.
DEFAULT_KD_PATHS = [
    r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\kd.exe",
    r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x86\kd.exe",
    r"C:\Program Files\Debugging Tools for Windows (x64)\kd.exe",
    r"C:\Program Files\Debugging Tools for Windows (x86)\kd.exe",

    # Microsoft Store WinDbg Preview locations
    os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\WindowsApps\kdX64.exe"),
    os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\WindowsApps\kdX86.exe"),
    os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\WindowsApps\kdARM64.exe"),
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
        kernel_connection: Optional[str] = None,
        cdb_path: Optional[str] = None,
        kd_path: Optional[str] = None,
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
            kernel_connection: Kernel debugging transport string (e.g., "net:port=50000,key=1.2.3.4",
                "com:port=COM1,baud=115200", "com:pipe,port=\\\\.\\pipe\\com_1", "1394:channel=0")
            cdb_path: Custom path to cdb.exe (used for all non-kernel sessions). If None, auto-detected.
            kd_path: Custom path to kd.exe (used for kernel sessions). If None, auto-detected.
            symbols_path: Custom symbols path. If None, uses default Windows symbols
            initial_commands: List of commands to run when CDB starts
            timeout: Timeout in seconds for waiting for CDB responses
            verbose: Whether to print additional debug information
            additional_args: Additional arguments to pass to cdb.exe / kd.exe

        Raises:
            CDBError: If cdb.exe / kd.exe cannot be found or started
            FileNotFoundError: If the dump file cannot be found
            ValueError: If invalid parameters are provided
        """
        # Validate that exactly one session type is provided
        provided = sum([
            bool(dump_path),
            bool(remote_connection),
            attach_process_id is not None,
            bool(attach_process_name),
            bool(kernel_connection),
        ])
        if provided == 0:
            raise ValueError("One of dump_path, remote_connection, attach_process_id, attach_process_name, or kernel_connection must be provided")
        if provided > 1:
            raise ValueError("dump_path, remote_connection, attach_process_id, attach_process_name, and kernel_connection are mutually exclusive")

        if dump_path and not os.path.isfile(dump_path):
            raise FileNotFoundError(f"Dump file not found: {dump_path}")

        self.dump_path = dump_path
        self.remote_connection = remote_connection
        self.attach_process_id = attach_process_id
        self.attach_process_name = attach_process_name
        self.kernel_connection = kernel_connection
        self.timeout = timeout
        self.verbose = verbose

        # Find the appropriate debugger executable.
        # Kernel sessions must use kd.exe (the Kernel Debugger).
        # All other session types use cdb.exe (the Console Debugger).
        if self.kernel_connection:
            self.cdb_path = self._find_kd_executable(kd_path)
            if not self.cdb_path:
                raise CDBError(
                    "Could not find kd.exe (Kernel Debugger). "
                    "Install Debugging Tools for Windows (Windows SDK) and ensure "
                    "kd.exe is present, or provide a custom path via kd_path."
                )
        else:
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
        elif self.kernel_connection:
            # -b: break into the debugger as soon as the target machine connects.
            # This matches the typical manual `kd -b -k <transport>` usage and
            # ensures the debugger is immediately at a kd> prompt after connection.
            cmd_args.extend(["-b", "-k", self.kernel_connection])

        # Add symbols path if provided
        if symbols_path:
            cmd_args.extend(["-y", symbols_path])

        # Add any additional arguments
        if additional_args:
            cmd_args.extend(additional_args)

        try:
            # Create a new process group for sessions where CTRL+BREAK is needed
            creationflags = 0
            if os.name == 'nt' and (self.remote_connection or self.attach_process_id is not None
                                    or self.attach_process_name or self.kernel_connection):
                creationflags = subprocess.CREATE_NEW_PROCESS_GROUP

            self.process = subprocess.Popen(
                cmd_args,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding='utf-8',
                errors='replace',
                bufsize=1,
                creationflags=creationflags,
            )
        except Exception as e:
            raise CDBError(f"Failed to start CDB process: {str(e)}")

        self.output_lines = []
        self.session_log: List[str] = []  # rolling log of all kd/cdb output
        self.lock = threading.Lock()
        self.ready_event = threading.Event()
        self._is_alive = True  # set to False when the CDB process exits
        self.reader_thread = threading.Thread(target=self._read_output)
        self.reader_thread.daemon = True
        self.reader_thread.start()

        # For kernel sessions the target machine may still be running when CDB
        # starts, so there is no debugger prompt to wait for.  Skip the initial
        # handshake; the caller is expected to send a break-in before issuing
        # any commands.
        if not self.kernel_connection:
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
        """Find the cdb.exe executable (user-mode debugger)."""
        if custom_path and os.path.isfile(custom_path):
            return custom_path

        for path in DEFAULT_CDB_PATHS:
            if os.path.isfile(path):
                return path

        return None

    def _find_kd_executable(self, custom_path: Optional[str] = None) -> Optional[str]:
        """Find the kd.exe executable (kernel-mode debugger)."""
        if custom_path and os.path.isfile(custom_path):
            return custom_path

        for path in DEFAULT_KD_PATHS:
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
                    # Append to rolling session log (cap at 5000 lines)
                    self.session_log.append(line)
                    if len(self.session_log) > 5000:
                        self.session_log = self.session_log[-5000:]
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

    def send_command(self, command: str, timeout: Optional[int] = None,
                     fire_and_forget: bool = False) -> List[str]:
        """
        Send a command to CDB and return the output.

        Args:
            command: The command to send
            timeout: Custom timeout for this command (overrides instance timeout)
            fire_and_forget: If True, write the command to stdin and return
                immediately without waiting for output.  Use this for commands
                that resume target execution (e.g. 'g', 'gh', 'gn') so the
                caller is not blocked until the next breakpoint.

        Returns:
            List of output lines from CDB (empty list when fire_and_forget=True)

        Raises:
            CDBError: If the command times out or CDB is not responsive
        """
        if not self.process or not self._is_alive:
            raise CDBError("CDB process is not running")
        if self.process.poll() is not None:
            self._is_alive = False
            raise CDBError("CDB process has exited")

        if fire_and_forget:
            try:
                self.process.stdin.write(f"{command}\n")
                self.process.stdin.flush()
            except IOError as e:
                raise CDBError(f"Failed to send command: {str(e)}")
            return []

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
                    elif self.kernel_connection:
                        # qd = quit debugger but leave the target machine running
                        self.process.stdin.write("qd\n")
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
            try:
                if self.process and self.process.stdin:
                    self.process.stdin.close()
            except Exception:
                pass
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

    def send_kernel_break(self) -> None:
        """Send a break-in request to the kernel target.

        Delivers CTRL_BREAK_EVENT to the kd process group.  kd intercepts this
        signal and transmits a debug break packet over the kernel transport,
        causing the target CPU(s) to pause.  This is equivalent to pressing
        Ctrl+Break in an interactive kd console.

        Note: writing '.break' to kd's stdin does NOT work while the target is
        running because kd stops reading stdin until it is at a prompt.

        Raises:
            CDBError: If the process is not running or the signal cannot be sent.
        """
        if not self.kernel_connection:
            raise CDBError("send_kernel_break is only valid for kernel debugging sessions")
        if not self.process or self.process.poll() is not None:
            raise CDBError("CDB process is not running")
        try:
            self.process.send_signal(signal.CTRL_BREAK_EVENT)
        except Exception as e:
            raise CDBError(f"Failed to send kernel break: {str(e)}")

    def get_session_log(self, max_lines: int = 200) -> List[str]:
        """Return the most recent lines of raw debugger output.

        Args:
            max_lines: Maximum number of lines to return (most recent).
        """
        with self.lock:
            return self.session_log[-max_lines:] if len(self.session_log) > max_lines else list(self.session_log)

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
        elif self.kernel_connection:
            return f"kernel:{self.kernel_connection}"
        else:
            raise CDBError("Session has no valid identifier")

    def __enter__(self):
        """Support for context manager protocol"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Clean up when exiting context manager"""
        self.shutdown()
