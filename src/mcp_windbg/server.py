import os
import traceback
import glob
import winreg
import logging
from typing import Dict, Optional
from contextlib import asynccontextmanager

from .cdb_session import CDBSession, CDBError
from .prompts import load_prompt

from mcp.shared.exceptions import McpError
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from mcp.types import (
    ErrorData,
    TextContent,
    Tool,
    Prompt,
    PromptArgument,
    PromptMessage,
    GetPromptResult,
    INVALID_PARAMS,
    INTERNAL_ERROR,
)
from pydantic import BaseModel, Field, model_validator

logger = logging.getLogger(__name__)

# Dictionary to store CDB sessions keyed by dump file path
active_sessions: Dict[str, CDBSession] = {}

def get_local_dumps_path() -> Optional[str]:
    """Get the local dumps path from the Windows registry."""
    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps"
        ) as key:
            dump_folder, _ = winreg.QueryValueEx(key, "DumpFolder")
            if os.path.exists(dump_folder) and os.path.isdir(dump_folder):
                return dump_folder
    except (OSError, WindowsError):
        # Registry key might not exist or other issues
        pass

    # Default Windows dump location
    default_path = os.path.join(os.environ.get("LOCALAPPDATA", ""), "CrashDumps")
    if os.path.exists(default_path) and os.path.isdir(default_path):
        return default_path

    return None

class OpenWindbgDump(BaseModel):
    """Parameters for analyzing a crash dump."""
    dump_path: str = Field(description="Path to the Windows crash dump file")
    include_stack_trace: bool = Field(description="Whether to include stack traces in the analysis")
    include_modules: bool = Field(description="Whether to include loaded module information")
    include_threads: bool = Field(description="Whether to include thread information")


class OpenWindbgRemote(BaseModel):
    """Parameters for connecting to a remote debug session."""
    connection_string: str = Field(description="Remote connection string (e.g., 'tcp:Port=5005,Server=192.168.0.100')")
    include_stack_trace: bool = Field(default=False, description="Whether to include stack traces in the analysis")
    include_modules: bool = Field(default=False, description="Whether to include loaded module information")
    include_threads: bool = Field(default=False, description="Whether to include thread information")


class AttachWindbgProcessParams(BaseModel):
    """Parameters for attaching to a local process."""
    pid: Optional[int] = Field(default=None, description="Process ID (PID) of the local process to attach to")
    process_name: Optional[str] = Field(default=None, description="Name of the local process to attach to (e.g., 'notepad.exe'). Use pid when possible for unambiguous targeting.")
    include_stack_trace: bool = Field(default=False, description="Whether to include the current stack trace after attaching")
    include_modules: bool = Field(default=False, description="Whether to include loaded module information")
    include_threads: bool = Field(default=False, description="Whether to include thread information")

    @model_validator(mode='after')
    def validate_attach_params(self):
        if self.pid is None and not self.process_name:
            raise ValueError("Either pid or process_name must be provided")
        if self.pid is not None and self.process_name:
            raise ValueError("pid and process_name are mutually exclusive")
        return self


class CloseWindbgProcessParams(BaseModel):
    """Parameters for detaching from a local process."""
    pid: Optional[int] = Field(default=None, description="Process ID (PID) that was attached")
    process_name: Optional[str] = Field(default=None, description="Process name that was attached")

    @model_validator(mode='after')
    def validate_params(self):
        if self.pid is None and not self.process_name:
            raise ValueError("Either pid or process_name must be provided")
        if self.pid is not None and self.process_name:
            raise ValueError("pid and process_name are mutually exclusive")
        return self


class ListLocalProcessesParams(BaseModel):
    """Parameters for listing local processes."""
    name_filter: Optional[str] = Field(default=None, description="Optional substring filter on process name (case-insensitive)")


class OpenWindbgKernelParams(BaseModel):
    """Parameters for connecting to a kernel debugging session."""
    kernel_connection: str = Field(
        description=(
            "Kernel debugging transport string. Examples:\n"
            "  KDNET (network):      net:port=50000,key=1.2.3.4\n"
            "  Serial:               com:port=COM1,baud=115200\n"
            "  Named pipe (VM):      com:pipe,port=\\\\\\.\\\\pipe\\\\com_1\n"
            "  USB 3.0:              usb3:targetname=MyTarget\n"
            "  IEEE 1394:            1394:channel=0"
        )
    )
    include_stack_trace: bool = Field(default=False, description="Whether to collect a kernel stack trace after connecting (requires the target to be at a break)")
    include_modules: bool = Field(default=False, description="Whether to collect loaded module information (requires the target to be at a break)")


class CloseWindbgKernelParams(BaseModel):
    """Parameters for disconnecting a kernel debugging session."""
    kernel_connection: str = Field(description="The kernel transport string used when opening the session")


class RunWindbgCmdParams(BaseModel):
    """Parameters for executing a WinDbg command."""
    dump_path: Optional[str] = Field(default=None, description="Path to the Windows crash dump file")
    connection_string: Optional[str] = Field(default=None, description="Remote connection string (e.g., 'tcp:Port=5005,Server=192.168.0.100')")
    pid: Optional[int] = Field(default=None, description="PID of the attached local process")
    process_name: Optional[str] = Field(default=None, description="Name of the attached local process")
    kernel_connection: Optional[str] = Field(default=None, description="Kernel debugging transport string (e.g., 'net:port=50000,key=1.2.3.4')")
    command: str = Field(description="WinDbg command to execute")
    no_wait: bool = Field(default=False, description="If True, send the command and return immediately without waiting for output. Use for commands that resume target execution such as 'g', 'gh', 'gn', 'gc'.")

    @model_validator(mode='after')
    def validate_connection_params(self):
        """Validate that exactly one session identifier is provided."""
        provided = sum([bool(self.dump_path), bool(self.connection_string), self.pid is not None,
                        bool(self.process_name), bool(self.kernel_connection)])
        if provided == 0:
            raise ValueError("One of dump_path, connection_string, pid, process_name, or kernel_connection must be provided")
        if provided > 1:
            raise ValueError("dump_path, connection_string, pid, process_name, and kernel_connection are mutually exclusive")
        return self


class CloseWindbgDumpParams(BaseModel):
    """Parameters for unloading a crash dump."""
    dump_path: str = Field(description="Path to the Windows crash dump file to unload")


class CloseWindbgRemoteParams(BaseModel):
    """Parameters for closing a remote debugging connection."""
    connection_string: str = Field(description="Remote connection string to close")


class ListWindbgDumpsParams(BaseModel):
    """Parameters for listing crash dumps in a directory."""
    directory_path: Optional[str] = Field(
        default=None,
        description="Directory path to search for dump files. If not specified, will use the configured dump path from registry."
    )
    recursive: bool = Field(
        default=False,
        description="Whether to search recursively in subdirectories"
    )


class GetSessionLogParams(BaseModel):
    """Parameters for retrieving raw debugger output from an active session."""
    kernel_connection: Optional[str] = Field(default=None, description="Kernel debugging transport string")
    dump_path: Optional[str] = Field(default=None, description="Path to the Windows crash dump file")
    connection_string: Optional[str] = Field(default=None, description="Remote connection string")
    pid: Optional[int] = Field(default=None, description="PID of the attached local process")
    process_name: Optional[str] = Field(default=None, description="Name of the attached local process")
    max_lines: int = Field(default=200, description="Maximum number of recent output lines to return (default 200)")

    @model_validator(mode='after')
    def validate_params(self):
        provided = sum([bool(self.kernel_connection), bool(self.dump_path),
                        bool(self.connection_string), self.pid is not None,
                        bool(self.process_name)])
        if provided == 0:
            raise ValueError("One session identifier must be provided")
        if provided > 1:
            raise ValueError("Only one session identifier may be provided")
        return self


class SendCtrlBreakParams(BaseModel):
    """Parameters for sending CTRL+BREAK to a CDB/WinDbg session."""
    dump_path: Optional[str] = Field(default=None, description="Path to the Windows crash dump file")
    connection_string: Optional[str] = Field(default=None, description="Remote connection string (e.g., 'tcp:Port=5005,Server=192.168.0.100')")
    pid: Optional[int] = Field(default=None, description="PID of the attached local process")
    process_name: Optional[str] = Field(default=None, description="Name of the attached local process")
    kernel_connection: Optional[str] = Field(default=None, description="Kernel debugging transport string. For kernel sessions this sends a '.break' command to pause the target machine.")

    @model_validator(mode='after')
    def validate_connection_params(self):
        provided = sum([bool(self.dump_path), bool(self.connection_string), self.pid is not None,
                        bool(self.process_name), bool(self.kernel_connection)])
        if provided == 0:
            raise ValueError("One of dump_path, connection_string, pid, process_name, or kernel_connection must be provided")
        if provided > 1:
            raise ValueError("dump_path, connection_string, pid, process_name, and kernel_connection are mutually exclusive")
        return self


def get_or_create_session(
    dump_path: Optional[str] = None,
    connection_string: Optional[str] = None,
    pid: Optional[int] = None,
    process_name: Optional[str] = None,
    kernel_connection: Optional[str] = None,
    cdb_path: Optional[str] = None,
    kd_path: Optional[str] = None,
    symbols_path: Optional[str] = None,
    timeout: int = 30,
    verbose: bool = False
) -> CDBSession:
    """Get an existing CDB session or create a new one."""
    provided = sum([bool(dump_path), bool(connection_string), pid is not None,
                    bool(process_name), bool(kernel_connection)])
    if provided == 0:
        raise ValueError("One of dump_path, connection_string, pid, process_name, or kernel_connection must be provided")
    if provided > 1:
        raise ValueError("dump_path, connection_string, pid, process_name, and kernel_connection are mutually exclusive")

    # Create session identifier
    if dump_path:
        session_id = os.path.abspath(dump_path)
    elif connection_string:
        session_id = f"remote:{connection_string}"
    elif pid is not None:
        session_id = f"pid:{pid}"
    elif kernel_connection:
        session_id = f"kernel:{kernel_connection}"
    else:
        session_id = f"process:{process_name}"

    if session_id not in active_sessions or active_sessions[session_id] is None:
        create_new = True
    else:
        existing = active_sessions[session_id]
        # Check whether the underlying CDB process is still alive.
        # If it has exited (e.g. remote connection dropped), discard the stale
        # session and create a fresh one so the caller gets a working session
        # rather than repeated timeouts against a dead process.
        if existing.process is None or not existing._is_alive or existing.process.poll() is not None:
            try:
                existing.shutdown()
            except Exception:
                pass
            del active_sessions[session_id]
            create_new = True
        else:
            create_new = False

    if create_new:
        try:
            session = CDBSession(
                dump_path=dump_path,
                remote_connection=connection_string,
                attach_process_id=pid,
                attach_process_name=process_name,
                kernel_connection=kernel_connection,
                cdb_path=cdb_path,
                kd_path=kd_path,
                symbols_path=symbols_path,
                timeout=timeout,
                verbose=verbose
            )
            active_sessions[session_id] = session
            return session
        except Exception as e:
            raise McpError(ErrorData(
                code=INTERNAL_ERROR,
                message=f"Failed to create CDB session: {str(e)}"
            ))

    return active_sessions[session_id]


def unload_session(
    dump_path: Optional[str] = None,
    connection_string: Optional[str] = None,
    pid: Optional[int] = None,
    process_name: Optional[str] = None,
    kernel_connection: Optional[str] = None,
) -> bool:
    """Unload and clean up a CDB session."""
    provided = sum([bool(dump_path), bool(connection_string), pid is not None,
                    bool(process_name), bool(kernel_connection)])
    if provided != 1:
        return False

    # Create session identifier
    if dump_path:
        session_id = os.path.abspath(dump_path)
    elif connection_string:
        session_id = f"remote:{connection_string}"
    elif pid is not None:
        session_id = f"pid:{pid}"
    elif kernel_connection:
        session_id = f"kernel:{kernel_connection}"
    else:
        session_id = f"process:{process_name}"

    if session_id in active_sessions and active_sessions[session_id] is not None:
        try:
            active_sessions[session_id].shutdown()
        except Exception:
            pass
        finally:
            del active_sessions[session_id]
        return True

    return False


def execute_common_analysis_commands(session: CDBSession) -> dict:
    """
    Execute common analysis commands and return the results.

    Returns a dictionary with the results of various analysis commands.
    """
    results = {}

    try:
        results["info"] = session.send_command(".lastevent")
        results["exception"] = session.send_command("!analyze -v")
        results["modules"] = session.send_command("lm")
        results["threads"] = session.send_command("~")
    except CDBError as e:
        results["error"] = str(e)

    return results


async def serve(
    cdb_path: Optional[str] = None,
    kd_path: Optional[str] = None,
    symbols_path: Optional[str] = None,
    timeout: int = 30,
    verbose: bool = False,
) -> None:
    """Run the WinDbg MCP server with stdio transport.

    Args:
        cdb_path: Optional custom path to cdb.exe
        kd_path: Optional custom path to kd.exe (kernel debugger)
        symbols_path: Optional custom symbols path
        timeout: Command timeout in seconds
        verbose: Whether to enable verbose output
    """
    server = _create_server(cdb_path, kd_path, symbols_path, timeout, verbose)

    options = server.create_initialization_options()
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, options, raise_exceptions=True)


async def serve_http(
    host: str = "127.0.0.1",
    port: int = 8000,
    cdb_path: Optional[str] = None,
    kd_path: Optional[str] = None,
    symbols_path: Optional[str] = None,
    timeout: int = 30,
    verbose: bool = False,
) -> None:
    """Run the WinDbg MCP server with Streamable HTTP transport.

    Args:
        host: Host to bind the HTTP server to
        port: Port to bind the HTTP server to
        cdb_path: Optional custom path to cdb.exe
        kd_path: Optional custom path to kd.exe (kernel debugger)
        symbols_path: Optional custom symbols path
        timeout: Command timeout in seconds
        verbose: Whether to enable verbose output
    """
    from starlette.applications import Starlette
    from starlette.routing import Mount
    from starlette.types import Receive, Scope, Send
    import uvicorn

    server = _create_server(cdb_path, kd_path, symbols_path, timeout, verbose)

    # Create the session manager
    session_manager = StreamableHTTPSessionManager(
        app=server,
        json_response=True,
    )

    # ASGI handler for streamable HTTP connections
    async def handle_streamable_http(scope: Scope, receive: Receive, send: Send) -> None:
        await session_manager.handle_request(scope, receive, send)

    @asynccontextmanager
    async def lifespan(app: Starlette):
        async with session_manager.run():
            yield

    app = Starlette(
        debug=verbose,
        routes=[
            Mount("/mcp", app=handle_streamable_http),
        ],
        lifespan=lifespan,
    )

    logger.info(f"Starting MCP WinDbg server with streamable-http transport on {host}:{port}")
    print(f"MCP WinDbg server running on http://{host}:{port}")
    print(f"  MCP endpoint: http://{host}:{port}/mcp")

    config = uvicorn.Config(app, host=host, port=port, log_level="info" if verbose else "warning")
    server_instance = uvicorn.Server(config)
    await server_instance.serve()


def _create_server(
    cdb_path: Optional[str] = None,
    kd_path: Optional[str] = None,
    symbols_path: Optional[str] = None,
    timeout: int = 30,
    verbose: bool = False,
) -> Server:
    """Create and configure the MCP server with all tools and prompts.

    Args:
        cdb_path: Optional custom path to cdb.exe
        kd_path: Optional custom path to kd.exe (kernel debugger)
        symbols_path: Optional custom symbols path
        timeout: Command timeout in seconds
        verbose: Whether to enable verbose output

    Returns:
        Configured Server instance
    """
    server = Server("mcp-windbg")

    @server.list_tools()
    async def list_tools() -> list[Tool]:
        return [
            Tool(
                name="open_windbg_dump",
                description="""
                Analyze a Windows crash dump file using WinDbg/CDB.
                This tool executes common WinDbg commands to analyze the crash dump and returns the results.
                """,
                inputSchema=OpenWindbgDump.model_json_schema(),
            ),
            Tool(
                name="open_windbg_remote",
                description="""
                Connect to a remote debugging session using WinDbg/CDB.
                This tool establishes a remote debugging connection and allows you to analyze the target process.
                """,
                inputSchema=OpenWindbgRemote.model_json_schema(),
            ),
            Tool(
                name="run_windbg_cmd",
                description="""
                Execute a specific WinDbg command on a loaded crash dump or remote session.
                This tool allows you to run any WinDbg command and get the output.
                """,
                inputSchema=RunWindbgCmdParams.model_json_schema(),
            ),
            Tool(
                name="send_ctrl_break",
                description="""
                Send a CTRL+BREAK event to the active CDB/WinDbg session, causing it to break in.
                Useful for interrupting a running target or breaking into a remote session.
                """,
                inputSchema=SendCtrlBreakParams.model_json_schema(),
            ),
            Tool(
                name="close_windbg_dump",
                description="""
                Unload a crash dump and release resources.
                Use this tool when you're done analyzing a crash dump to free up resources.
                """,
                inputSchema=CloseWindbgDumpParams.model_json_schema(),
            ),
            Tool(
                name="close_windbg_remote",
                description="""
                Close a remote debugging connection and release resources.
                Use this tool when you're done with a remote debugging session to free up resources.
                """,
                inputSchema=CloseWindbgRemoteParams.model_json_schema(),
            ),
            Tool(
                name="list_windbg_dumps",
                description="""
                List Windows crash dump files in the specified directory.
                This tool helps you discover available crash dumps that can be analyzed.
                """,
                inputSchema=ListWindbgDumpsParams.model_json_schema(),
            ),
            Tool(
                name="attach_windbg_process",
                description="""
                Attach to a running local Windows process using WinDbg/CDB.
                You can specify either the process PID or the process name.
                After attaching, the target process is paused and can be inspected or resumed.
                Use 'list_local_processes' first to discover available processes and their PIDs.
                """,
                inputSchema=AttachWindbgProcessParams.model_json_schema(),
            ),
            Tool(
                name="close_windbg_process",
                description="""
                Detach WinDbg/CDB from a previously attached local process and resume it.
                Use this tool when you are done debugging the process.
                """,
                inputSchema=CloseWindbgProcessParams.model_json_schema(),
            ),
            Tool(
                name="list_local_processes",
                description="""
                List running local Windows processes with their PIDs and names.
                Use this tool to discover candidate processes before attaching with 'attach_windbg_process'.
                """,
                inputSchema=ListLocalProcessesParams.model_json_schema(),
            ),
            Tool(
                name="open_windbg_kernel",
                description="""
                Connect to a live kernel debugging session using WinDbg/CDB.

                Supported transports:
                  - KDNET (network):   net:port=50000,key=1.2.3.4
                  - Serial:            com:port=COM1,baud=115200
                  - Named pipe (VM):   com:pipe,port=\\\\.\\pipe\\com_1
                  - USB 3.0:           usb3:targetname=MyTarget
                  - IEEE 1394:         1394:channel=0

                Prerequisites on the target machine:
                  bcdedit /debug on
                  bcdedit /dbgsettings net hostip:<HOST_IP> port:50000   (for KDNET)
                  (reboot the target after changing settings)

                After this tool returns, the target may still be running.
                Use 'send_ctrl_break' with kernel_connection to pause it, then
                use 'run_windbg_cmd' with kernel_connection to send commands.
                When finished, use 'close_windbg_kernel' to detach gracefully.
                """,
                inputSchema=OpenWindbgKernelParams.model_json_schema(),
            ),
            Tool(
                name="close_windbg_kernel",
                description="""
                Disconnect from a kernel debugging session.
                Sends 'qd' (quit and detach) so the target machine keeps running.
                """,
                inputSchema=CloseWindbgKernelParams.model_json_schema(),
            ),
            Tool(
                name="get_session_log",
                description="""
                Retrieve the raw debugger output accumulated so far from an active session.
                Use this to see connection messages, kd prompts, and any output that
                occurred before or between commands (e.g., the 'Connected to Windows...'
                messages printed by kd when the target VM connects).
                Supports all session types: kernel, dump, remote, and local process.
                """,
                inputSchema=GetSessionLogParams.model_json_schema(),
            ),
        ]

    @server.call_tool()
    async def call_tool(name, arguments: dict) -> list[TextContent]:
        try:
            if name == "open_windbg_dump":
                # Check if dump_path is missing or empty
                if "dump_path" not in arguments or not arguments.get("dump_path"):
                    local_dumps_path = get_local_dumps_path()
                    dumps_found_text = ""

                    if local_dumps_path:
                        # Find dump files in the local dumps directory
                        search_pattern = os.path.join(local_dumps_path, "*.*dmp")
                        dump_files = glob.glob(search_pattern)

                        if dump_files:
                            dumps_found_text = f"\n\nI found {len(dump_files)} crash dump(s) in {local_dumps_path}:\n\n"
                            for i, dump_file in enumerate(dump_files[:10]):  # Limit to 10 dumps to avoid clutter
                                try:
                                    size_mb = round(os.path.getsize(dump_file) / (1024 * 1024), 2)
                                except (OSError, IOError):
                                    size_mb = "unknown"

                                dumps_found_text += f"{i+1}. {dump_file} ({size_mb} MB)\n"

                            if len(dump_files) > 10:
                                dumps_found_text += f"\n... and {len(dump_files) - 10} more dump files.\n"

                            dumps_found_text += "\nYou can analyze one of these dumps by specifying its path."

                    return [TextContent(
                        type="text",
                        text=f"Please provide a path to a crash dump file to analyze.{dumps_found_text}\n\n"
                              f"You can use the 'list_windbg_dumps' tool to discover available crash dumps."
                    )]

                args = OpenWindbgDump(**arguments)
                session = get_or_create_session(
                    dump_path=args.dump_path, cdb_path=cdb_path, kd_path=kd_path, symbols_path=symbols_path, timeout=timeout, verbose=verbose
                )

                results = []

                crash_info = session.send_command(".lastevent")
                results.append("### Crash Information\n```\n" + "\n".join(crash_info) + "\n```\n\n")

                # Run !analyze -v
                analysis = session.send_command("!analyze -v")
                results.append("### Crash Analysis\n```\n" + "\n".join(analysis) + "\n```\n\n")

                # Optional
                if args.include_stack_trace:
                    stack = session.send_command("kb")
                    results.append("### Stack Trace\n```\n" + "\n".join(stack) + "\n```\n\n")

                if args.include_modules:
                    modules = session.send_command("lm")
                    results.append("### Loaded Modules\n```\n" + "\n".join(modules) + "\n```\n\n")

                if args.include_threads:
                    threads = session.send_command("~")
                    results.append("### Threads\n```\n" + "\n".join(threads) + "\n```\n\n")

                return [TextContent(type="text", text="".join(results))]

            elif name == "open_windbg_remote":
                args = OpenWindbgRemote(**arguments)
                session = get_or_create_session(
                    connection_string=args.connection_string, cdb_path=cdb_path, kd_path=kd_path, symbols_path=symbols_path, timeout=timeout, verbose=verbose
                )

                results = []

                # Get target information for remote debugging
                target_info = session.send_command("!peb")
                results.append("### Target Process Information\n```\n" + "\n".join(target_info) + "\n```\n\n")

                # Get current state
                current_state = session.send_command("r")
                results.append("### Current Registers\n```\n" + "\n".join(current_state) + "\n```\n\n")

                # Optional
                if args.include_stack_trace:
                    stack = session.send_command("kb")
                    results.append("### Stack Trace\n```\n" + "\n".join(stack) + "\n```\n\n")

                if args.include_modules:
                    modules = session.send_command("lm")
                    results.append("### Loaded Modules\n```\n" + "\n".join(modules) + "\n```\n\n")

                if args.include_threads:
                    threads = session.send_command("~")
                    results.append("### Threads\n```\n" + "\n".join(threads) + "\n```\n\n")

                return [TextContent(
                    type="text",
                    text="".join(results)
                )]

            elif name == "run_windbg_cmd":
                args = RunWindbgCmdParams(**arguments)
                session = get_or_create_session(
                    dump_path=args.dump_path, connection_string=args.connection_string,
                    pid=args.pid, process_name=args.process_name,
                    kernel_connection=args.kernel_connection,
                    cdb_path=cdb_path, kd_path=kd_path, symbols_path=symbols_path, timeout=timeout, verbose=verbose
                )

                # Commands that resume target execution never return a prompt while
                # the target is running.  Detect them automatically so the caller
                # doesn't have to remember to set no_wait=True.
                _RESUME_CMDS = frozenset({"g", "gh", "gn", "gc", "gu", "go"})
                fire_and_forget = args.no_wait or args.command.strip().lower() in _RESUME_CMDS

                output = session.send_command(args.command, fire_and_forget=fire_and_forget)

                if fire_and_forget:
                    return [TextContent(
                        type="text",
                        text=f"Command sent: `{args.command}`\n\nTarget is now running. Use `send_ctrl_break` to pause it again, or `get_session_log` to see output."
                    )]

                return [TextContent(
                    type="text",
                    text=f"Command: {args.command}\n\nOutput:\n```\n" + "\n".join(output) + "\n```"
                )]

            elif name == "send_ctrl_break":
                args = SendCtrlBreakParams(**arguments)
                session = get_or_create_session(
                    dump_path=args.dump_path, connection_string=args.connection_string,
                    pid=args.pid, process_name=args.process_name,
                    kernel_connection=args.kernel_connection,
                    cdb_path=cdb_path, kd_path=kd_path, symbols_path=symbols_path, timeout=timeout, verbose=verbose
                )
                if args.kernel_connection:
                    # For kernel sessions, use the CDB .break command over the transport
                    session.send_kernel_break()
                    target = f"kernel: {args.kernel_connection}"
                else:
                    session.send_ctrl_break()
                    if args.dump_path:
                        target = args.dump_path
                    elif args.connection_string:
                        target = f"remote: {args.connection_string}"
                    elif args.pid is not None:
                        target = f"pid: {args.pid}"
                    else:
                        target = f"process: {args.process_name}"
                return [TextContent(
                    type="text",
                    text=f"Sent break-in to CDB session ({target}). The target should pause shortly."
                )]

            elif name == "close_windbg_dump":
                args = CloseWindbgDumpParams(**arguments)
                success = unload_session(dump_path=args.dump_path)
                if success:
                    return [TextContent(
                        type="text",
                        text=f"Successfully unloaded crash dump: {args.dump_path}"
                    )]
                else:
                    return [TextContent(
                        type="text",
                        text=f"No active session found for crash dump: {args.dump_path}"
                    )]

            elif name == "close_windbg_remote":
                args = CloseWindbgRemoteParams(**arguments)
                success = unload_session(connection_string=args.connection_string)
                if success:
                    return [TextContent(
                        type="text",
                        text=f"Successfully closed remote connection: {args.connection_string}"
                    )]
                else:
                    return [TextContent(
                        type="text",
                        text=f"No active session found for remote connection: {args.connection_string}"
                    )]

            elif name == "list_windbg_dumps":
                args = ListWindbgDumpsParams(**arguments)

                if args.directory_path is None:
                    args.directory_path = get_local_dumps_path()
                    if args.directory_path is None:
                        raise McpError(ErrorData(
                            code=INVALID_PARAMS,
                            message="No directory path specified and no default dump path found in registry."
                        ))

                if not os.path.exists(args.directory_path) or not os.path.isdir(args.directory_path):
                    raise McpError(ErrorData(
                        code=INVALID_PARAMS,
                        message=f"Directory not found: {args.directory_path}"
                    ))

                # Determine search pattern based on recursion flag
                search_pattern = os.path.join(args.directory_path, "**", "*.*dmp") if args.recursive else os.path.join(args.directory_path, "*.*dmp")

                # Find all dump files
                dump_files = glob.glob(search_pattern, recursive=args.recursive)

                # Sort alphabetically for consistent results
                dump_files.sort()

                if not dump_files:
                    return [TextContent(
                        type="text",
                        text=f"No crash dump files (*.*dmp) found in {args.directory_path}"
                    )]

                # Format the results
                result_text = f"Found {len(dump_files)} crash dump file(s) in {args.directory_path}:\n\n"
                for i, dump_file in enumerate(dump_files):
                    # Get file size in MB
                    try:
                        size_mb = round(os.path.getsize(dump_file) / (1024 * 1024), 2)
                    except (OSError, IOError):
                        size_mb = "unknown"

                    result_text += f"{i+1}. {dump_file} ({size_mb} MB)\n"

                return [TextContent(
                    type="text",
                    text=result_text
                )]

            elif name == "attach_windbg_process":
                args = AttachWindbgProcessParams(**arguments)
                session = get_or_create_session(
                    pid=args.pid, process_name=args.process_name,
                    cdb_path=cdb_path, kd_path=kd_path, symbols_path=symbols_path, timeout=timeout, verbose=verbose
                )

                results = []

                # Get target process information
                target_info = session.send_command("!peb")
                results.append("### Target Process Information\n```\n" + "\n".join(target_info) + "\n```\n\n")

                # Get current registers
                reg_info = session.send_command("r")
                results.append("### Current Registers\n```\n" + "\n".join(reg_info) + "\n```\n\n")

                if args.include_stack_trace:
                    stack = session.send_command("kb")
                    results.append("### Stack Trace\n```\n" + "\n".join(stack) + "\n```\n\n")

                if args.include_modules:
                    modules = session.send_command("lm")
                    results.append("### Loaded Modules\n```\n" + "\n".join(modules) + "\n```\n\n")

                if args.include_threads:
                    threads = session.send_command("~")
                    results.append("### Threads\n```\n" + "\n".join(threads) + "\n```\n\n")

                target_label = f"PID {args.pid}" if args.pid is not None else args.process_name
                return [TextContent(
                    type="text",
                    text=f"Successfully attached to process ({target_label}).\n\n" + "".join(results)
                )]

            elif name == "close_windbg_process":
                args = CloseWindbgProcessParams(**arguments)
                success = unload_session(pid=args.pid, process_name=args.process_name)
                target_label = f"PID {args.pid}" if args.pid is not None else args.process_name
                if success:
                    return [TextContent(
                        type="text",
                        text=f"Successfully detached from process ({target_label}) and resumed it."
                    )]
                else:
                    return [TextContent(
                        type="text",
                        text=f"No active session found for process ({target_label})."
                    )]

            elif name == "list_local_processes":
                args = ListLocalProcessesParams(**arguments)
                import subprocess as _sp
                proc = _sp.run(
                    ["tasklist", "/fo", "csv", "/nh"],
                    capture_output=True, text=True
                )
                lines = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
                # Each CSV line: "Image Name","PID","Session Name","Session#","Mem Usage"
                processes = []
                for line in lines:
                    parts = [p.strip('"') for p in line.split('","')]
                    if len(parts) >= 2:
                        name_col = parts[0]
                        pid_col = parts[1]
                        if args.name_filter and args.name_filter.lower() not in name_col.lower():
                            continue
                        processes.append((name_col, pid_col))

                if not processes:
                    filter_note = f" matching '{args.name_filter}'" if args.name_filter else ""
                    return [TextContent(
                        type="text",
                        text=f"No running processes found{filter_note}."
                    )]

                result_text = f"Found {len(processes)} running process(es):\n\n"
                result_text += f"{'PID':<8} {'Name'}\n"
                result_text += "-" * 50 + "\n"
                for proc_name, proc_pid in processes:
                    result_text += f"{proc_pid:<8} {proc_name}\n"

                return [TextContent(type="text", text=result_text)]

            elif name == "open_windbg_kernel":
                args = OpenWindbgKernelParams(**arguments)
                session = get_or_create_session(
                    kernel_connection=args.kernel_connection,
                    cdb_path=cdb_path, kd_path=kd_path, symbols_path=symbols_path, timeout=timeout, verbose=verbose
                )

                # At this point CDB is running but the target may still be executing.
                # Attempt to collect info only if optional flags are set (they imply
                # the caller has already ensured the target is at a break).
                results = []
                results.append(
                    f"### Kernel Debug Session Established\n"
                    f"Transport: `{args.kernel_connection}`\n\n"
                    f"CDB is running and waiting for the target machine.\n\n"
                    f"**Next steps:**\n"
                    f"- If the target machine is running, call `send_ctrl_break` with "
                    f"`kernel_connection` to pause it.\n"
                    f"- Once the target is at a break, use `run_windbg_cmd` with "
                    f"`kernel_connection` to send any WinDbg/CDB command.\n"
                    f"- Useful first commands: `vertarget`, `!analyze -v`, `k`, `lm`, `!process 0 0`\n"
                    f"- When finished, call `close_windbg_kernel` to detach without crashing the target.\n"
                )

                if args.include_stack_trace:
                    try:
                        stack = session.send_command("k")
                        results.append("\n### Kernel Stack Trace\n```\n" + "\n".join(stack) + "\n```\n")
                    except CDBError as e:
                        results.append(f"\n*Stack trace unavailable (target may still be running): {e}*\n")

                if args.include_modules:
                    try:
                        modules = session.send_command("lm")
                        results.append("\n### Loaded Modules\n```\n" + "\n".join(modules) + "\n```\n")
                    except CDBError as e:
                        results.append(f"\n*Module list unavailable (target may still be running): {e}*\n")

                return [TextContent(type="text", text="".join(results))]

            elif name == "close_windbg_kernel":
                args = CloseWindbgKernelParams(**arguments)
                success = unload_session(kernel_connection=args.kernel_connection)
                if success:
                    return [TextContent(
                        type="text",
                        text=f"Kernel debug session closed (`{args.kernel_connection}`). "
                             f"The target machine has been detached and continues running."
                    )]
                else:
                    return [TextContent(
                        type="text",
                        text=f"No active kernel debug session found for: {args.kernel_connection}"
                    )]

            elif name == "get_session_log":
                args = GetSessionLogParams(**arguments)
                session_id_map = {
                    'kernel': args.kernel_connection,
                    'dump': args.dump_path,
                    'remote': args.connection_string,
                    'pid': args.pid,
                    'process': args.process_name,
                }
                # Build the session_id key used in active_sessions
                if args.dump_path:
                    sid = os.path.abspath(args.dump_path)
                elif args.connection_string:
                    sid = f"remote:{args.connection_string}"
                elif args.pid is not None:
                    sid = f"pid:{args.pid}"
                elif args.kernel_connection:
                    sid = f"kernel:{args.kernel_connection}"
                else:
                    sid = f"process:{args.process_name}"

                session = active_sessions.get(sid)
                if session is None:
                    return [TextContent(type="text", text=f"No active session found for: {sid}")]

                lines = session.get_session_log(max_lines=args.max_lines)
                if not lines:
                    return [TextContent(type="text", text="Session log is empty (no output received yet).")]

                return [TextContent(
                    type="text",
                    text=f"### Session Log (last {len(lines)} lines)\n```\n" + "\n".join(lines) + "\n```"
                )]

            raise McpError(ErrorData(
                code=INVALID_PARAMS,
                message=f"Unknown tool: {name}"
            ))

        except McpError:
            raise
        except Exception as e:
            traceback_str = traceback.format_exc()
            raise McpError(ErrorData(
                code=INTERNAL_ERROR,
                message=f"Error executing tool {name}: {str(e)}\n{traceback_str}"
            ))

    # Prompt constants
    DUMP_TRIAGE_PROMPT_NAME = "dump-triage"
    DUMP_TRIAGE_PROMPT_TITLE = "Crash Dump Triage Analysis"
    DUMP_TRIAGE_PROMPT_DESCRIPTION = "Comprehensive single crash dump analysis with detailed metadata extraction and structured reporting"

    KERNEL_TRIAGE_PROMPT_NAME = "kernel-triage"
    KERNEL_TRIAGE_PROMPT_TITLE = "Kernel Debug Session Triage"
    KERNEL_TRIAGE_PROMPT_DESCRIPTION = "Live kernel debugging session analysis via KD transport (KDNET, serial, named pipe, USB, 1394)"

    MEMORY_LEAK_PROMPT_NAME = "memory-leak"
    MEMORY_LEAK_PROMPT_TITLE = "Memory Leak Analysis"
    MEMORY_LEAK_PROMPT_DESCRIPTION = "Systematic memory leak detection and analysis for live processes or full-heap crash dumps, including kernel pool leak analysis"

    CRASH_INVESTIGATION_PROMPT_NAME = "crash-investigation"
    CRASH_INVESTIGATION_PROMPT_TITLE = "Crash Root-Cause Investigation"
    CRASH_INVESTIGATION_PROMPT_DESCRIPTION = "Step-by-step interactive root-cause investigation for Windows crashes - covers access violations, heap corruption, stack overflows, C++ exceptions, and more"

    HANDLE_LEAK_PROMPT_NAME = "handle-leak"
    HANDLE_LEAK_PROMPT_TITLE = "Handle Leak Investigation"
    HANDLE_LEAK_PROMPT_DESCRIPTION = "Systematic investigation of Windows kernel handle leaks (files, events, mutexes, registry keys, threads, sockets, etc.) using !handle, !htrace, and GFlags htc"

    # Define available prompts for triage analysis
    @server.list_prompts()
    async def list_prompts() -> list[Prompt]:
        return [
            Prompt(
                name=DUMP_TRIAGE_PROMPT_NAME,
                title=DUMP_TRIAGE_PROMPT_TITLE,
                description=DUMP_TRIAGE_PROMPT_DESCRIPTION,
                arguments=[
                    PromptArgument(
                        name="dump_path",
                        description="Path to the Windows crash dump file to analyze (optional - will prompt if not provided)",
                        required=False,
                    ),
                ],
            ),
            Prompt(
                name=KERNEL_TRIAGE_PROMPT_NAME,
                title=KERNEL_TRIAGE_PROMPT_TITLE,
                description=KERNEL_TRIAGE_PROMPT_DESCRIPTION,
                arguments=[
                    PromptArgument(
                        name="kernel_connection",
                        description="KD transport string (e.g., 'net:port=50000,key=1.2.3.4'). Optional - will prompt if not provided.",
                        required=False,
                    ),
                ],
            ),
            Prompt(
                name=MEMORY_LEAK_PROMPT_NAME,
                title=MEMORY_LEAK_PROMPT_TITLE,
                description=MEMORY_LEAK_PROMPT_DESCRIPTION,
                arguments=[
                    PromptArgument(
                        name="target",
                        description="Process name, PID, dump file path, or kernel connection string. Optional - will guide you through selection if not provided.",
                        required=False,
                    ),
                ],
            ),
            Prompt(
                name=CRASH_INVESTIGATION_PROMPT_NAME,
                title=CRASH_INVESTIGATION_PROMPT_TITLE,
                description=CRASH_INVESTIGATION_PROMPT_DESCRIPTION,
                arguments=[
                    PromptArgument(
                        name="dump_path",
                        description="Path to the Windows crash dump file to investigate. Optional - can also attach to a live process.",
                        required=False,
                    ),
                ],
            ),
            Prompt(
                name=HANDLE_LEAK_PROMPT_NAME,
                title=HANDLE_LEAK_PROMPT_TITLE,
                description=HANDLE_LEAK_PROMPT_DESCRIPTION,
                arguments=[
                    PromptArgument(
                        name="target",
                        description="Process name or PID to investigate for handle leaks. Optional - will guide you through identification if not provided.",
                        required=False,
                    ),
                ],
            ),
        ]

    @server.get_prompt()
    async def get_prompt(name: str, arguments: dict | None) -> GetPromptResult:
        if arguments is None:
            arguments = {}

        if name == DUMP_TRIAGE_PROMPT_NAME:
            dump_path = arguments.get("dump_path", "")
            try:
                prompt_content = load_prompt("dump-triage")
            except FileNotFoundError as e:
                raise McpError(ErrorData(
                    code=INTERNAL_ERROR,
                    message=f"Prompt file not found: {e}"
                ))

            # If dump_path is provided, prepend it to the prompt
            if dump_path:
                prompt_text = f"**Dump file to analyze:** {dump_path}\n\n{prompt_content}"
            else:
                prompt_text = prompt_content

            return GetPromptResult(
                description=DUMP_TRIAGE_PROMPT_DESCRIPTION,
                messages=[
                    PromptMessage(
                        role="user",
                        content=TextContent(
                            type="text",
                            text=prompt_text
                        ),
                    ),
                ],
            )

        elif name == KERNEL_TRIAGE_PROMPT_NAME:
            kernel_connection = arguments.get("kernel_connection", "")
            try:
                prompt_content = load_prompt("kernel-triage")
            except FileNotFoundError as e:
                raise McpError(ErrorData(
                    code=INTERNAL_ERROR,
                    message=f"Prompt file not found: {e}"
                ))

            if kernel_connection:
                prompt_text = f"**Kernel connection transport:** `{kernel_connection}`\n\n{prompt_content}"
            else:
                prompt_text = prompt_content

            return GetPromptResult(
                description=KERNEL_TRIAGE_PROMPT_DESCRIPTION,
                messages=[
                    PromptMessage(
                        role="user",
                        content=TextContent(
                            type="text",
                            text=prompt_text
                        ),
                    ),
                ],
            )

        elif name == MEMORY_LEAK_PROMPT_NAME:
            target = arguments.get("target", "")
            try:
                prompt_content = load_prompt("memory-leak")
            except FileNotFoundError as e:
                raise McpError(ErrorData(
                    code=INTERNAL_ERROR,
                    message=f"Prompt file not found: {e}"
                ))

            if target:
                prompt_text = f"**Target to analyze:** {target}\n\n{prompt_content}"
            else:
                prompt_text = prompt_content

            return GetPromptResult(
                description=MEMORY_LEAK_PROMPT_DESCRIPTION,
                messages=[
                    PromptMessage(
                        role="user",
                        content=TextContent(
                            type="text",
                            text=prompt_text
                        ),
                    ),
                ],
            )

        elif name == CRASH_INVESTIGATION_PROMPT_NAME:
            dump_path = arguments.get("dump_path", "")
            try:
                prompt_content = load_prompt("crash-investigation")
            except FileNotFoundError as e:
                raise McpError(ErrorData(
                    code=INTERNAL_ERROR,
                    message=f"Prompt file not found: {e}"
                ))

            if dump_path:
                prompt_text = f"**Dump file to investigate:** {dump_path}\n\n{prompt_content}"
            else:
                prompt_text = prompt_content

            return GetPromptResult(
                description=CRASH_INVESTIGATION_PROMPT_DESCRIPTION,
                messages=[
                    PromptMessage(
                        role="user",
                        content=TextContent(
                            type="text",
                            text=prompt_text
                        ),
                    ),
                ],
            )

        elif name == HANDLE_LEAK_PROMPT_NAME:
            target = arguments.get("target", "")
            try:
                prompt_content = load_prompt("handle-leak")
            except FileNotFoundError as e:
                raise McpError(ErrorData(
                    code=INTERNAL_ERROR,
                    message=f"Prompt file not found: {e}"
                ))

            if target:
                prompt_text = f"**Target to investigate:** {target}\n\n{prompt_content}"
            else:
                prompt_text = prompt_content

            return GetPromptResult(
                description=HANDLE_LEAK_PROMPT_DESCRIPTION,
                messages=[
                    PromptMessage(
                        role="user",
                        content=TextContent(
                            type="text",
                            text=prompt_text
                        ),
                    ),
                ],
            )

        else:
            raise McpError(ErrorData(
                code=INVALID_PARAMS,
                message=f"Unknown prompt: {name}"
            ))

    return server


# Clean up function to ensure all sessions are closed when the server exits
def cleanup_sessions():
    """Close all active CDB sessions."""
    for dump_path, session in active_sessions.items():
        try:
            if session is not None:
                session.shutdown()
        except Exception:
            pass
    active_sessions.clear()


# Register cleanup on module exit
import atexit
atexit.register(cleanup_sessions)
